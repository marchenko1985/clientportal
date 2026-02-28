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
/// <see cref="Subscribe"/> and <see cref="Unsubscribe"/> (or
/// repeated <see cref="Unsubscribe"/> calls) as clients connect and disconnect;
/// <see cref="Connection"/> is only instructed to send an upstream
/// <c>smd+{conid}+{...}</c> or <c>umd+{conid}+{}</c> message when this class
/// determines it is actually necessary.
/// </para>
///
/// <para>
/// <b>Ref-count pattern:</b> an integer reference count is maintained per conid.
/// The count is incremented on every <see cref="Subscribe"/> call and decremented on
/// every <see cref="Unsubscribe"/> call. The upstream IBKR subscription is started
/// only when the ref count transitions from 0 to 1 (i.e. the first subscriber), and
/// the upstream unsubscribe is scheduled only when the ref count drops back to 0
/// (i.e. the last subscriber leaves). This avoids redundant subscribe/unsubscribe
/// round-trips for every individual client arrival or departure.
/// </para>
///
/// <para>
/// <b>Field-union logic:</b> different clients may request different subsets of
/// fields for the same conid (e.g. client A wants <c>["31","84"]</c>, client B wants
/// <c>["31","86"]</c>). IBKR requires a single field list per subscription. This
/// class therefore accumulates the superset of all fields ever requested for a conid
/// (<see cref="ConidFields"/>) and sends the growing union upstream whenever a new field is
/// added. Fields are never removed from this union even when a client that requested
/// them disconnects — doing so would require tracking per-client field sets and
/// re-computing a new union, adding significant complexity for minimal gain, since
/// IBKR charges no extra cost for receiving additional fields.
/// </para>
///
/// <para>
/// <b>Delayed unsubscribe:</b> when the last subscriber for a conid
/// leaves, the upstream unsubscribe is deliberately deferred by
/// <see cref="Config.UnsubscribeDelay"/>. If a browser client
/// reconnects within that window (e.g. after a page reload or a brief network
/// hiccup) and re-subscribes, the pending timer is cancelled and no upstream
/// unsubscribe is ever sent — the IBKR subscription stays live and market data
/// keeps flowing uninterrupted. This avoids an unnecessary subscribe→unsubscribe→
/// subscribe round-trip and the associated latency gap in data delivery.
/// </para>
/// </summary>
public class Subscriptions(Action<int> onDelayedUnsubscribe, IOptions<Config> options, ILogger<Subscriptions> logger)
{
    private readonly TimeSpan _unsubscribeDelay = options.Value.UnsubscribeDelay;

    /// <summary>
    /// Guards all mutable state in this class. A single coarse-grained lock is used
    /// because subscription operations are infrequent relative to market-data ticks,
    /// so the contention cost is negligible compared to the simplicity gained.
    /// </summary>
    private readonly Lock _lock = new();

    /// <summary>
    /// Reference count per conid — how many browser clients currently hold an active
    /// subscription to this contract. A count of 0 means no client is subscribed
    /// (the entry is removed rather than stored as 0 to keep the dictionary clean).
    /// </summary>
    private Dictionary<int, int> RefCounts { get; } = [];

    /// <summary>
    /// Holds the <see cref="CancellationTokenSource"/> for each conid whose upstream
    /// unsubscribe timer is currently running (i.e. ref count just reached 0 but the
    /// configured grace period has not yet elapsed). Presence in this dictionary means
    /// IBKR is still subscribed even though no client is currently tracking the conid.
    /// </summary>
    private Dictionary<int, CancellationTokenSource> PendingUnsubscribes { get; } = [];

    /// <summary>
    /// The cumulative union of all field codes ever requested for each conid.
    /// Once a field code is added for a conid it is never removed, so the set only
    /// grows. This is the field list that was most recently sent (or will be sent) to
    /// IBKR in the <c>smd+{conid}+{"fields":[...]}</c> message.
    /// </summary>
    private Dictionary<int, HashSet<string>> ConidFields { get; } = [];

    /// <summary>
    /// Monotonic version per conid used to invalidate stale delayed-unsubscribe callbacks.
    /// </summary>
    private Dictionary<int, long> UnsubscribeVersions { get; } = [];

    /// <summary>
    /// Public state for debugging purposes
    /// </summary>
    public IReadOnlyList<(int conid, int refs, int fields, bool pendingUnsubscribe)> State
    {
        get
        {
            lock (_lock)
            {
                var conids = RefCounts.Keys.Union(PendingUnsubscribes.Keys).ToList();
                return conids
                    .Select(conid =>
                    {
                        RefCounts.TryGetValue(conid, out var refs);
                        var fields = ConidFields.TryGetValue(conid, out var codes) ? codes.Count : 0;
                        return (conid, refs, fields, PendingUnsubscribes.ContainsKey(conid));
                    })
                    .ToArray();
            }
        }
    }

    /// <summary>
    /// Records a new client subscription for the given contract and requested fields,
    /// updating internal ref counts and the cumulative field union.
    ///
    /// <para>
    /// <b>Pending-unsubscribe cancellation:</b> if a delayed-unsubscribe timer is
    /// currently running for this conid (because the previous last subscriber recently
    /// left), that timer is cancelled before incrementing the ref count. This means
    /// the upstream IBKR subscription was never torn down, so no re-subscribe message
    /// needs to be sent — unless new field codes are being requested that were not
    /// previously tracked.
    /// </para>
    ///
    /// <para>
    /// <b>Upstream message decision:</b> the caller (<see cref="Hub"/>) uses
    /// the returned value to decide whether and what to send to <see cref="Connection"/>:
    /// <list type="bullet">
    ///   <item>
    ///     <description>
    ///       If <c>upstreamFields</c> is non-null, send an <c>smd</c> subscribe with
    ///       that full field union (either first subscribe or union expansion).
    ///     </description>
    ///   </item>
    ///   <item>
    ///     <description>
    ///       If <c>upstreamFields</c> is <see langword="null"/>, all requested fields
    ///       are already being streamed — no upstream message is needed.
    ///     </description>
    ///   </item>
    /// </list>
    /// </para>
    /// </summary>
    /// <param name="conid">
    /// The IBKR contract identifier (e.g. <c>265598</c> for AAPL).
    /// </param>
    /// <param name="requestedFieldCodes">
    /// The field codes this particular client wants (e.g. <c>["31", "84"]</c>).
    /// Must not be empty. Values are the raw IBKR numeric strings.
    /// </param>
    /// <returns>
    /// The full updated field list to send to IBKR, or <see langword="null"/> if no
    /// upstream message is required because all requested fields are already included
    /// in the existing subscription.
    /// </returns>
    public string[]? Subscribe(int conid, string[] requestedFieldCodes)
    {
        lock (_lock)
        {
            var hadPending = PendingUnsubscribes.TryGetValue(conid, out var cts);
            if (hadPending)
            {
                cts!.Cancel();
                PendingUnsubscribes.Remove(conid);
                if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Cancelled delayed unsubscribe for conid {Conid}", conid);
            }

            RefCounts.TryGetValue(conid, out var count);
            RefCounts[conid] = count + 1;

            if (!ConidFields.TryGetValue(conid, out var existing))
            {
                ConidFields[conid] = [.. requestedFieldCodes];
                if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("First subscriber for conid {Conid}; refs={RefCount}, fields={FieldCount}", conid, RefCounts[conid], requestedFieldCodes.Length);
                return [.. requestedFieldCodes];
            }

            var newCodes = requestedFieldCodes.Except(existing).ToArray();
            if (newCodes.Length == 0)
            {
                if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Subscribe no-op for conid {Conid}; refs={RefCount}, fields={FieldCount}", conid, RefCounts[conid], existing.Count);
                return null;
            }

            foreach (var code in newCodes) existing.Add(code);
            if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Expanded fields for conid {Conid}; refs={RefCount}, added={AddedFields}, total={TotalFields}", conid, RefCounts[conid], newCodes.Length, existing.Count);
            return [.. existing];
        }
    }

    /// <summary>
    /// Records the departure of one client subscriber for the given contract.
    ///
    /// <para>
    /// The ref count for <paramref name="conid"/> is decremented. If the count was
    /// already 0 or the conid is not tracked at all the call is a no-op (defensive
    /// guard against double-unsubscribe).
    /// </para>
    ///
    /// <para>
    /// <b>When the last subscriber leaves</b> (ref count reaches 0):
    /// <list type="number">
    ///   <item>
    ///     <description>
    ///       The ref count entry for this conid is removed immediately. The cumulative
    ///       field set is retained during the grace window so a quick re-subscribe can
    ///       avoid a redundant upstream <c>smd+</c> message.
    ///     </description>
    ///   </item>
    ///   <item>
    ///     <description>
    ///       A <see cref="Task.Delay(int, CancellationToken)"/> timer of
    ///       <see cref="Config.UnsubscribeDelay"/> is started. Its
    ///       <see cref="CancellationTokenSource"/> is stored in
    ///       <see cref="PendingUnsubscribes"/> so that a subsequent <see cref="Subscribe"/>
    ///       call can cancel it within the grace period.
    ///     </description>
    ///   </item>
    ///   <item>
    ///     <description>
    ///       If the timer fires without being cancelled, the
    ///       delayed-unsubscribe callback supplied at construction
    ///       time is invoked with the conid, and the pending entry plus field set are
    ///       cleaned up.
    ///       The callback is responsible for sending <c>umd+{conid}+{}</c> to IBKR
    ///       via <see cref="Connection"/>.
    ///     </description>
    ///   </item>
    /// </list>
    /// </para>
    ///
    /// <para>
    /// When there are still other subscribers (ref count remains above 0) only the
    /// count is decremented — no timer is started and no upstream message is needed.
    /// </para>
    /// </summary>
    /// <param name="conid">
    /// The IBKR contract identifier for which one client subscription is ending.
    /// </param>
    public void Unsubscribe(int conid)
    {
        lock (_lock)
        {
            RefCounts.TryGetValue(conid, out var count);
            if (count <= 1)
            {
                if (count != 1) return;
                RefCounts.Remove(conid);

                var cts = new CancellationTokenSource();
                PendingUnsubscribes[conid] = cts;
                var nextVersion = UnsubscribeVersions.GetValueOrDefault(conid) + 1;
                UnsubscribeVersions[conid] = nextVersion;
                if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Last subscriber left for conid {Conid}; scheduling delayed unsubscribe in {Delay}", conid, _unsubscribeDelay);

                _ = Task.Delay(_unsubscribeDelay, cts.Token).ContinueWith(t =>
                {
                    if (t.IsCanceled)
                    {
                        cts.Dispose();
                        return;
                    }

                    var shouldUnsubscribe = false;
                    lock (_lock)
                    {
                        var isCurrentVersion = UnsubscribeVersions.TryGetValue(conid, out var currentVersion) && currentVersion == nextVersion;
                        var hasSubscribers = RefCounts.ContainsKey(conid);
                        if (isCurrentVersion && !hasSubscribers && PendingUnsubscribes.Remove(conid))
                        {
                            ConidFields.Remove(conid);
                            UnsubscribeVersions.Remove(conid);
                            shouldUnsubscribe = true;
                        }
                    }

                    if (shouldUnsubscribe)
                    {
                        if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Delayed unsubscribe fired for conid {Conid}", conid);
                        onDelayedUnsubscribe(conid);
                    }
                    else
                    {
                        if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Ignored stale delayed unsubscribe for conid {Conid}", conid);
                    }

                    cts.Dispose();
                }, TaskScheduler.Default);
            }
            else
            {
                RefCounts[conid] = count - 1;
                if (logger.IsEnabled(LogLevel.Debug)) logger.LogDebug("Decremented refs for conid {Conid}; refs={RefCount}", conid, RefCounts[conid]);
            }
        }
    }

}
