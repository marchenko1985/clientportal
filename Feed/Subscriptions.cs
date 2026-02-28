using Microsoft.Extensions.Options;

namespace Feed;

/// <summary>
/// Manages the mapping between downstream browser-client subscriptions and the single
/// upstream IBKR WebSocket subscription for each contract (conid).
///
/// <para>
/// <b>Role in the system:</b> Many browser clients may simultaneously request market
/// data for the same contract. Rather than opening a separate IBKR subscription for
/// each client, this class multiplexes them: exactly one upstream subscription exists
/// per conid, shared by all interested clients. <see cref="Hub"/> calls
/// <see cref="Subscribe"/> and <see cref="Unsubscribe"/> as clients connect and
/// disconnect; <see cref="Connection"/> is only instructed to send an upstream
/// <c>smd+{conid}+{...}</c> or <c>umd+{conid}+{}</c> message when this class
/// determines it is actually necessary.
/// </para>
///
/// <para>
/// <b>Per-client field tracking:</b> each client's requested field set is tracked
/// individually. The upstream IBKR subscription reflects the union of all current
/// clients' fields for each conid. When a client disconnects, the union is
/// recomputed; if it has shrunk the upstream subscription is updated (umd+smd) after
/// the <see cref="Config.UnsubscribeDelay"/> grace period. This avoids consuming
/// unnecessary IBKR market data lines for fields no longer needed by any client.
/// </para>
///
/// <para>
/// <b>Delayed change:</b> when the last subscriber for a conid leaves, or when the
/// field union shrinks after a client disconnect, the upstream change is deliberately
/// deferred by <see cref="Config.UnsubscribeDelay"/>. If a browser client
/// reconnects within that window the pending timer is cancelled and the IBKR
/// subscription stays live uninterrupted.
/// </para>
/// </summary>
public class Subscriptions(Action<int, string[]?> onDelayedChange, IOptions<Config> options, ILogger<Subscriptions> logger) : IDisposable
{
    /// <summary>
    /// Cancelled on <see cref="Dispose"/> (application shutdown) to immediately abort
    /// all pending delayed-change timers so the process exits cleanly without waiting
    /// for the full <see cref="Config.UnsubscribeDelay"/> to elapse.
    /// </summary>
    private readonly CancellationTokenSource _shutdownCts = new();
    private readonly TimeSpan _unsubscribeDelay = options.Value.UnsubscribeDelay;

    /// <summary>
    /// Guards all mutable state in this class. A single coarse-grained lock is used
    /// because subscription operations are infrequent relative to market-data ticks,
    /// so the contention cost is negligible compared to the simplicity gained.
    /// </summary>
    private readonly Lock _lock = new();

    /// <summary>
    /// Per-client field sets: conid → clientId → fields this client requested.
    /// </summary>
    private Dictionary<int, Dictionary<Guid, HashSet<string>>> _clientFields = [];

    /// <summary>
    /// The field set currently active on IBKR (what we last sent / intend to send)
    /// for each conid.
    /// </summary>
    private Dictionary<int, HashSet<string>> _ibkrFields = [];

    /// <summary>
    /// Delayed-change timer per conid, cancelled on a new subscribe within the grace window.
    /// </summary>
    private Dictionary<int, CancellationTokenSource> _pending = [];

    /// <summary>
    /// Monotonic version per conid used to invalidate stale delayed-change callbacks.
    /// </summary>
    private Dictionary<int, long> _versions = [];

    /// <summary>
    /// Snapshot of current subscription state for the <c>/status</c> debug endpoint.
    /// </summary>
    public IReadOnlyList<(int conid, int clients, int fields, bool pendingChange)> State
    {
        get
        {
            lock (_lock)
            {
                var conids = _clientFields.Keys.Union(_pending.Keys).ToList();
                return conids
                    .Select(conid =>
                    {
                        var clients = _clientFields.TryGetValue(conid, out var cf) ? cf.Count : 0;
                        var fields = _ibkrFields.TryGetValue(conid, out var ibkr) ? ibkr.Count : 0;
                        return (conid, clients, fields, _pending.ContainsKey(conid));
                    })
                    .ToArray();
            }
        }
    }

    /// <summary>
    /// Records a new client subscription for the given contract and requested fields,
    /// updating per-client field tracking and the upstream IBKR field union.
    ///
    /// <para>
    /// <b>Pending-change cancellation:</b> if a delayed-change timer is currently
    /// running for this conid (because the previous last subscriber recently left or
    /// the field set shrank), that timer is cancelled. The IBKR subscription was
    /// never torn down or changed, so no re-subscribe message is needed unless new
    /// field codes are requested.
    /// </para>
    ///
    /// <para>
    /// <b>Upstream message decision:</b> returns the new full field union to send to
    /// IBKR, or <see langword="null"/> if all requested fields are already included
    /// in the existing IBKR subscription (no upstream message needed).
    /// </para>
    /// </summary>
    /// <param name="conid">The IBKR contract identifier (e.g. <c>265598</c> for AAPL).</param>
    /// <param name="clientId">Unique identifier of the connecting browser client.</param>
    /// <param name="requestedFields">
    /// The field codes this particular client wants (e.g. <c>["31", "84"]</c>).
    /// Must not be empty.
    /// </param>
    /// <returns>
    /// The full updated field list to send to IBKR, or <see langword="null"/> if no
    /// upstream message is required.
    /// </returns>
    public string[]? Subscribe(int conid, Guid clientId, string[] requestedFields)
    {
        lock (_lock)
        {
            // Cancel any pending delayed change for this conid.
            if (_pending.TryGetValue(conid, out var cts))
            {
                cts.Cancel();
                _pending.Remove(conid);
                if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Cancelled delayed change for conid {Conid}", conid);
            }

            // Upsert per-client field set.
            if (!_clientFields.TryGetValue(conid, out var clients))
            {
                clients = [];
                _clientFields[conid] = clients;
            }
            clients[clientId] = [.. requestedFields];

            // Compute new union across all clients.
            var newUnion = clients.Values.SelectMany(f => f).ToHashSet();

            // Compare with what IBKR currently has.
            var ibkr = _ibkrFields.GetValueOrDefault(conid);

            if (ibkr != null && newUnion.IsSubsetOf(ibkr))
            {
                if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Subscribe no-op for conid {Conid}; clients={Clients}, fields={Fields}", conid, clients.Count, ibkr.Count);
                return null;
            }

            _ibkrFields[conid] = newUnion;
            if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Subscribe for conid {Conid}; clients={Clients}, fields={Fields}", conid, clients.Count, newUnion.Count);
            return [.. newUnion];
        }
    }

    /// <summary>
    /// Records the departure of one client subscriber for the given contract.
    ///
    /// <para>
    /// The client's field set is removed and the union is recomputed. If the union
    /// has not changed (another client still needs the same fields) the call is a
    /// no-op. Otherwise a delayed-change timer is started. When it fires, the
    /// callback supplied at construction time is invoked:
    /// <list type="bullet">
    ///   <item><description>
    ///     <c>null</c> fields — no clients remain; caller should send <c>umd</c> and
    ///     remove the snapshot cache.
    ///   </description></item>
    ///   <item><description>
    ///     non-null fields — union shrank; caller should re-subscribe with new fields
    ///     (Connection.Subscribe handles the umd+smd sequence).
    ///   </description></item>
    /// </list>
    /// </para>
    /// </summary>
    /// <param name="conid">The IBKR contract identifier for which one client subscription is ending.</param>
    /// <param name="clientId">Unique identifier of the disconnecting browser client.</param>
    public void Unsubscribe(int conid, Guid clientId)
    {
        lock (_lock)
        {
            if (!_clientFields.TryGetValue(conid, out var clients))
                return;

            clients.Remove(clientId);
            if (clients.Count == 0) _clientFields.Remove(conid);

            // Compute new union.
            var newUnion = clients.Values.SelectMany(f => f).ToHashSet();

            var ibkr = _ibkrFields.GetValueOrDefault(conid) ?? [];

            if (newUnion.SetEquals(ibkr))
            {
                if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Unsubscribe no-op for conid {Conid}; fields unchanged", conid);
                return;
            }

            // Field set changed — schedule a delayed update.
            var pendingCts = new CancellationTokenSource();
            _pending[conid] = pendingCts;
            var nextVersion = _versions.GetValueOrDefault(conid) + 1;
            _versions[conid] = nextVersion;

            if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Scheduling delayed change for conid {Conid} in {Delay}", conid, _unsubscribeDelay);

            // Link the per-conid CTS and the shutdown CTS so that either a new Subscribe
            // or application shutdown will abort the delay immediately.
            var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(pendingCts.Token, _shutdownCts.Token);
            _ = Task.Delay(_unsubscribeDelay, linkedCts.Token).ContinueWith(t =>
            {
                linkedCts.Dispose();
                if (t.IsCanceled)
                {
                    pendingCts.Dispose();
                    return;
                }

                string[]? fieldsToSend = null;
                var shouldFire = false;

                lock (_lock)
                {
                    var isCurrentVersion = _versions.TryGetValue(conid, out var currentVersion) && currentVersion == nextVersion;
                    if (isCurrentVersion && _pending.Remove(conid))
                    {
                        // Recompute union with current client state (may have changed).
                        var currentClients = _clientFields.GetValueOrDefault(conid);
                        var currentUnion = currentClients != null
                            ? currentClients.Values.SelectMany(f => f).ToHashSet()
                            : [];

                        var currentIbkr = _ibkrFields.GetValueOrDefault(conid) ?? [];

                        if (!currentUnion.SetEquals(currentIbkr))
                        {
                            if (currentUnion.Count == 0)
                            {
                                _ibkrFields.Remove(conid);
                                _versions.Remove(conid);
                                fieldsToSend = null;
                            }
                            else
                            {
                                _ibkrFields[conid] = currentUnion;
                                fieldsToSend = [.. currentUnion];
                            }
                            shouldFire = true;
                        }
                    }
                }

                if (shouldFire)
                {
                    if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Delayed change fired for conid {Conid}, newFields={Fields}", conid, fieldsToSend?.Length.ToString() ?? "null");
                    onDelayedChange(conid, fieldsToSend);
                }
                else
                {
                    if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Ignored stale delayed change for conid {Conid}", conid);
                }

                pendingCts.Dispose();
            }, TaskScheduler.Default);
        }
    }

    /// <summary>
    /// Cancels all pending delayed-change timers immediately so the process can exit
    /// cleanly without waiting for <see cref="Config.UnsubscribeDelay"/> to elapse.
    /// </summary>
    public void Dispose()
    {
        _shutdownCts.Cancel();
        _shutdownCts.Dispose();
    }
}
