using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Microsoft.Extensions.Options;

namespace Feed;

/// <summary>
/// Maintains the single upstream WebSocket connection to the IBKR Trader Workstation
/// (TWS) gateway and fans out received market-data ticks to <see cref="Snapshots"/>
/// for downstream browser clients.
///
/// <para>
/// <b>Role in the system:</b> this service sits between the IBKR server and the
/// browser-facing <c>Hub</c>. It owns exactly one <see cref="ClientWebSocket"/>
/// at a time and serialises all outgoing frames through a <see cref="SemaphoreSlim"/>
/// so that concurrent callers (heartbeat loop, subscribe/unsubscribe, flush) never
/// violate the WebSocket protocol's requirement that at most one send is in-flight on
/// a given connection at any moment.
/// </para>
///
/// <para>
/// <b>Lifecycle:</b>
/// <list type="number">
///   <item>
///     <description>
///       The service waits for <see cref="SessionService.WaitForSessionAsync"/> to
///       complete, guaranteeing that the OAuth handshake has finished and a valid
///       session cookie + access token are available before any WebSocket connection
///       attempt is made.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="ConnectAndRunAsync"/> opens the WebSocket to
///       <c>wss://api.ibkr.com/v1/api/ws?oauth_token={AccessToken}</c> with a
///       <c>Cookie: api={session}</c> header, then immediately sends a <c>tic</c>
///       heartbeat. IBKR closes idle connections within a few seconds of the
///       handshake, so the first heartbeat must be sent before the configured
///       periodic timer fires.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="HeartbeatAsync"/> sends a <c>tic</c> frame at
///       <see cref="InteractiveBrokersOptions.PingInterval"/> cadence to keep
///       the connection alive.
///     </description>
///   </item>
///   <item>
///     <description>
///       <see cref="ReceiveLoopAsync"/> reads frames from IBKR and dispatches them
///       to <see cref="OnMessage"/>. Two topic types are handled:
///       <c>sts</c> (authentication status) and <c>smd+{conid}</c> (market data).
///     </description>
///   </item>
///   <item>
///     <description>
///       When <c>sts</c> carries <c>authenticated=true</c>,
///       <see cref="IsAuthenticated"/> is set and <see cref="FlushPendingAsync"/>
///       replays every entry in <c>_pendingSubscriptions</c> so that all previously
///       requested market-data feeds are re-established after a reconnect.
///     </description>
///   </item>
///   <item>
///     <description>
///       If the connection drops for any reason, <see cref="ExecuteAsync"/> catches
///       the exception, marks <see cref="IsAuthenticated"/> as <see langword="false"/>,
///       waits for an exponentially increasing back-off delay (30 s, 60 s, 120 s …
///       capped at 600 s), then reconnects. Because <c>_pendingSubscriptions</c>
///       survives reconnects (it is a persistent <see cref="ConcurrentDictionary"/>
///       that is only mutated by <see cref="Subscribe"/> and
///       <see cref="Unsubscribe"/>), all subscriptions that were active before the
///       drop are automatically replayed once the new connection becomes authenticated.
///     </description>
///   </item>
/// </list>
/// </para>
/// </summary>
public class Connection(
    Snapshots snapshots,
    IOptions<Config> options,
    IConfiguration configuration,
    ILogger<Connection> logger) : BackgroundService
{
    /// <summary>
    /// The persistent map of conid → field-code array for every upstream market-data
    /// subscription that is currently desired by <c>Hub</c>.
    ///
    /// <para>
    /// This dictionary is written by <see cref="Subscribe"/> and <see cref="Unsubscribe"/>
    /// (which are called from <c>Hub</c>) and read by <see cref="FlushPendingAsync"/>
    /// after every successful reconnect. Because the dictionary outlives individual
    /// WebSocket connections, subscriptions survive network drops and reconnects
    /// without any coordination required from callers.
    /// </para>
    /// </summary>
    private readonly ConcurrentDictionary<int, string[]> _pendingSubscriptions = new();

    /// <summary>
    /// Enforces single-sender semantics on the active WebSocket connection.
    ///
    /// <para>
    /// The WebSocket protocol requires that no two send operations overlap on the
    /// same connection. <see cref="ClientWebSocket.SendAsync"/> is not thread-safe
    /// when called concurrently. Three independent asynchronous paths may try to send
    /// at the same time: the heartbeat loop, the initial post-connect
    /// <c>tic</c>, and calls from <see cref="Subscribe"/> / <see cref="Unsubscribe"/>
    /// or <see cref="FlushPendingAsync"/>. The semaphore (capacity 1) ensures these
    /// paths are serialised without blocking threads: each awaiter suspends until the
    /// semaphore is released by the current sender.
    /// </para>
    /// </summary>
    private readonly SemaphoreSlim _sendLock = new(1, 1);

    /// <summary>The active upstream WebSocket connection, or <see langword="null"/> when disconnected.</summary>
    private ClientWebSocket? _ws;

    /// <summary>
    /// Gets a value indicating whether the upstream IBKR WebSocket connection has
    /// received a <c>sts</c> message with <c>authenticated=true</c> and is therefore
    /// ready to receive and deliver market-data subscriptions.
    ///
    /// <para>
    /// <b>How callers use this:</b> <c>Hub</c> reads this property when
    /// composing status messages to browser clients so that the UI can indicate
    /// whether the upstream data feed is live. The property is set to
    /// <see langword="true"/> inside <see cref="OnMessage"/> when the authenticated
    /// status is confirmed, and reset to <see langword="false"/> whenever the
    /// connection is torn down (including during reconnect back-off periods).
    /// </para>
    ///
    /// <para>
    /// Reads of this property are not synchronised with writes. Callers should treat
    /// the value as advisory — a momentary mismatch between the actual connection
    /// state and the property value is possible and harmless.
    /// </para>
    /// </summary>
    private int _isAuthenticated;
    public bool IsAuthenticated => Volatile.Read(ref _isAuthenticated) == 1;

    private void SetAuthenticated(bool authenticated)
    {
        Volatile.Write(ref _isAuthenticated, authenticated ? 1 : 0);
    }

    /// <summary>
    /// Records a request to receive market data for the specified contract and
    /// adds or replaces the entry in <c>_pendingSubscriptions</c> so that the
    /// subscription is replayed after every reconnect.
    ///
    /// <para>
    /// If the upstream connection is currently authenticated, the subscribe message
    /// is sent immediately. Otherwise the entry is queued in
    /// <c>_pendingSubscriptions</c> and will be flushed by <see cref="FlushPendingAsync"/>
    /// once authentication is confirmed.
    /// </para>
    ///
    /// <para>
    /// This method is called by <c>Hub</c> when a browser client requests
    /// market data for a contract that has no existing upstream subscription (or when
    /// a new field code must be added to an existing subscription).
    /// </para>
    /// </summary>
    /// <param name="conid">The IBKR contract identifier (e.g. <c>265598</c> for AAPL).</param>
    /// <param name="fieldCodes">
    /// The field codes to request from IBKR (e.g. <c>["31", "84", "86"]</c>). This
    /// array should represent the full union of fields needed for this conid as
    /// computed by <c>Subscriptions</c>, not just the incremental addition.
    /// </param>
    public void Subscribe(int conid, string[] fieldCodes)
    {
        _pendingSubscriptions[conid] = fieldCodes;
        if (IsAuthenticated) _ = SendAsync(BuildSmdMessage(conid, fieldCodes));
    }

    /// <summary>
    /// Removes the upstream subscription for the specified contract and, if the
    /// connection is currently authenticated, sends an <c>umd+{conid}+{}</c>
    /// unsubscribe message to IBKR.
    ///
    /// <para>
    /// After this call returns, the conid is no longer present in
    /// <c>_pendingSubscriptions</c>, so the subscription will not be replayed if
    /// the connection reconnects.
    /// </para>
    ///
    /// <para>
    /// This method is called by <c>Hub</c> (via <c>Subscriptions</c>'s
    /// delayed-unsubscribe callback) once all browser clients that were watching a
    /// given contract have disconnected and the configured grace period has elapsed.
    /// </para>
    /// </summary>
    /// <param name="conid">The IBKR contract identifier to stop streaming.</param>
    public void Unsubscribe(int conid)
    {
        _pendingSubscriptions.TryRemove(conid, out _);
        if (IsAuthenticated) _ = SendAsync($"umd+{conid}+{{}}");
    }

    /// <summary>
    /// Main background-service loop. Waits for the OAuth session, then repeatedly
    /// calls <see cref="ConnectAndRunAsync"/> with exponential back-off between
    /// attempts until the application stops.
    /// </summary>
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var attempt = 0;
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ConnectAndRunAsync(stoppingToken);
                attempt = 0;
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { logger.LogError(ex, "[Socket] Connection error"); }

            if (stoppingToken.IsCancellationRequested) break;
            attempt++;
            var delaySec = (int)Math.Min(30 * Math.Pow(2, attempt - 1), 600);
            logger.LogInformation("[Socket] Reconnecting in {Delay}s (attempt {Attempt})", delaySec, attempt);
            try { await Task.Delay(TimeSpan.FromSeconds(delaySec), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>
    /// Opens a fresh WebSocket connection to IBKR, sends the initial heartbeat,
    /// then runs the heartbeat and receive loops concurrently until one of them
    /// terminates (due to a server close frame, network error, or cancellation).
    ///
    /// <para>
    /// <b>Initial <c>tic</c> heartbeat:</b> IBKR closes connections that are idle
    /// immediately after the TCP/TLS handshake. The <c>tic</c> frame is therefore
    /// sent as soon as <see cref="ClientWebSocket.ConnectAsync"/> returns — before
    /// the first configured periodic heartbeat would fire — to signal liveness to
    /// the IBKR gateway.
    /// </para>
    ///
    /// <para>
    /// <b>Teardown:</b> when either loop exits, the linked
    /// <see cref="CancellationTokenSource"/> is cancelled so that the other loop
    /// is also stopped. <see cref="IsAuthenticated"/> is reset to
    /// <see langword="false"/> and the socket is closed gracefully (if still open)
    /// and disposed.
    /// </para>
    /// </summary>
    private async Task ConnectAndRunAsync(CancellationToken ct)
    {
        var baseAddress = configuration["Config:BaseAddress"]
            ?? throw new InvalidOperationException("Missing IBKR base address");

        var baseUri = new Uri(baseAddress);

        _ws = new ClientWebSocket();
        try
        {
            logger.LogInformation("[Socket] Connecting to {Uri}", baseUri);
            await _ws.ConnectAsync(baseUri, ct);
            logger.LogInformation("[Socket] Connected — waiting for sts");

            SetAuthenticated(false);
            await SendAsync("tic", ct); // send immediately; IBKR closes idle connections

            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            try
            {
                await Task.WhenAny(HeartbeatAsync(cts.Token), ReceiveLoopAsync(cts.Token));
            }
            finally
            {
                await cts.CancelAsync();
            }
        }
        finally
        {
            SetAuthenticated(false);
            if (_ws.State == WebSocketState.Open)
                try { await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "closing", CancellationToken.None); } catch { }
            _ws.Dispose();
            _ws = null;
        }
    }

    /// <summary>
    /// Sends a <c>tic</c> keepalive frame to IBKR at
    /// <see cref="InteractiveBrokersOptions.PingInterval"/> cadence for as long
    /// as the connection is active.
    ///
    /// <para>
    /// Uses <see cref="PeriodicTimer"/> rather than <c>Task.Delay</c> in a loop so
    /// that timer drift does not accumulate across ticks. The loop exits cleanly
    /// when <paramref name="ct"/> is cancelled (i.e. when the connection is being
    /// torn down).
    /// </para>
    /// </summary>
    private async Task HeartbeatAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(options.Value.PingInterval);
        while (await timer.WaitForNextTickAsync(ct))
            await SendAsync("tic", ct);
    }

    /// <summary>
    /// Continuously reads WebSocket frames from the upstream IBKR connection,
    /// reassembles fragmented messages, and passes each complete UTF-8 text
    /// message to <see cref="OnMessage"/>.
    ///
    /// <para>
    /// The receive buffer is 64 KiB. Fragmented messages (where
    /// <see cref="WebSocketReceiveResult.EndOfMessage"/> is <see langword="false"/>)
    /// are accumulated in a <see cref="MemoryStream"/> and only dispatched once the
    /// final fragment arrives.
    /// </para>
    ///
    /// <para>
    /// A <see cref="WebSocketMessageType.Close"/> frame causes the loop to return
    /// immediately, triggering the teardown path in <see cref="ConnectAndRunAsync"/>.
    /// </para>
    /// </summary>
    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var buffer = new byte[64 * 1024];
        while (!ct.IsCancellationRequested)
        {
            using var ms = new MemoryStream();
            WebSocketReceiveResult result;
            do
            {
                result = await _ws!.ReceiveAsync(buffer, ct);
                if (result.MessageType == WebSocketMessageType.Close) { logger.LogInformation("[Socket] Close frame received"); return; }
                ms.Write(buffer, 0, result.Count);
            } while (!result.EndOfMessage);

            OnMessage(Encoding.UTF8.GetString(ms.ToArray()), ct);
        }
    }

    /// <summary>
    /// Parses and dispatches a single message received from the upstream IBKR
    /// WebSocket connection.
    ///
    /// <para>
    /// <b>Handled topics:</b>
    /// <list type="bullet">
    ///   <item>
    ///     <term><c>sts</c></term>
    ///     <description>
    ///       Authentication status. When <c>args.authenticated</c> is
    ///       <see langword="true"/>, <see cref="IsAuthenticated"/> is set and
    ///       <see cref="FlushPendingAsync"/> is called to replay all queued upstream
    ///       subscriptions. This handles the case where subscriptions were registered
    ///       before the connection authenticated (e.g. immediately after a reconnect).
    ///     </description>
    ///   </item>
    ///   <item>
    ///     <term><c>smd+{conid}</c></term>
    ///     <description>
    ///       Market-data tick for a contract. Every JSON key whose name is a pure
    ///       integer string (e.g. <c>"31"</c>, <c>"84"</c>) is treated as an IBKR
    ///       field code. The raw string value is written to <see cref="Snapshots"/>
    ///       so that downstream browser clients can read the latest value.
    ///       Non-numeric keys such as <c>"_updated"</c>, <c>"conid"</c>, and
    ///       <c>"topic"</c> are silently skipped.
    ///     </description>
    ///   </item>
    /// </list>
    /// </para>
    ///
    /// <para>
    /// All exceptions are caught and logged as warnings so that a malformed message
    /// cannot terminate the receive loop.
    /// </para>
    /// </summary>
    private void OnMessage(string text, CancellationToken ct)
    {
        try
        {
            var data = JsonNode.Parse(text)?.AsObject();
            if (data == null) return;
            var topic = data["topic"]?.GetValue<string>();
            if (topic == null) return;

            if (topic == "sts")
            {
                var authenticated = data["args"]?["authenticated"]?.GetValue<bool>() ?? false;
                var wasAuthenticated = IsAuthenticated;
                SetAuthenticated(authenticated);
                if (wasAuthenticated != authenticated)
                {
                    logger.LogInformation("[Socket] sts authenticated={Auth}", authenticated);
                }

                if (!wasAuthenticated && authenticated)
                {
                    _ = FlushPendingAsync(ct);
                }
            }
            else if (topic.StartsWith("smd+") && int.TryParse(topic.AsSpan(4), out var conid))
            {
                var ticks = DateTime.UtcNow.Ticks;
                foreach (var (key, value) in data)
                    if (int.TryParse(key, out _) && value is JsonValue jv && jv.TryGetValue<string>(out var raw))
                        snapshots.Write(conid, key, raw, ticks);
            }
        }
        catch (Exception ex) { logger.LogWarning(ex, "[Socket] Message parse error"); }
    }

    /// <summary>
    /// Sends a fresh <c>smd+{conid}+{...}</c> subscribe message for every entry
    /// currently in <c>_pendingSubscriptions</c>.
    ///
    /// <para>
    /// This is called once per connection, immediately after IBKR confirms
    /// authentication via a <c>sts</c> message. Because <c>_pendingSubscriptions</c>
    /// is a persistent dictionary that is not cleared on disconnect, this single call
    /// is sufficient to restore the full set of active market-data feeds after any
    /// reconnect — no coordination with <c>Hub</c> is required.
    /// </para>
    /// </summary>
    private async Task FlushPendingAsync(CancellationToken ct)
    {
        foreach (var (conid, fields) in _pendingSubscriptions)
            await SendAsync(BuildSmdMessage(conid, fields), ct);
    }

    /// <summary>
    /// Serialises and sends a UTF-8 text frame over the active WebSocket connection,
    /// acquiring <c>_sendLock</c> first to guarantee that at most one send is
    /// in-flight at a time.
    ///
    /// <para>
    /// <b>Why the semaphore is required:</b> <see cref="ClientWebSocket.SendAsync"/>
    /// throws <see cref="InvalidOperationException"/> if a concurrent send is already
    /// in progress. Three independent asynchronous paths call this method:
    /// <list type="bullet">
    ///   <item><description>The initial <c>tic</c> sent right after connect.</description></item>
    ///   <item><description>The periodic heartbeat timer (every 60 s).</description></item>
    ///   <item><description>
    ///     Fire-and-forget calls from <see cref="Subscribe"/>, <see cref="Unsubscribe"/>,
    ///     and <see cref="FlushPendingAsync"/>.
    ///   </description></item>
    /// </list>
    /// The semaphore serialises all of these without blocking threads — each caller
    /// suspends asynchronously until the slot is available.
    /// </para>
    ///
    /// <para>
    /// Send failures (e.g. if the socket has already closed by the time the lock is
    /// acquired) are caught and logged rather than re-thrown so that the caller's
    /// fire-and-forget invocation does not produce an unobserved exception.
    /// </para>
    /// </summary>
    /// <param name="message">The text payload to send.</param>
    /// <param name="ct">Cancellation token; passed to both the semaphore wait and the send.</param>
    private async Task SendAsync(string message, CancellationToken ct = default)
    {
        await _sendLock.WaitAsync(ct);
        try
        {
            if (_ws?.State == WebSocketState.Open)
                await _ws.SendAsync(Encoding.UTF8.GetBytes(message), WebSocketMessageType.Text, true, ct);
        }
        catch (Exception ex) { logger.LogWarning(ex, "[Socket] Send failed: {Msg}", message); }
        finally { _sendLock.Release(); }
    }

    /// <summary>
    /// Builds the IBKR wire-format subscribe message for the given contract and
    /// field codes.
    ///
    /// <para>
    /// The resulting string has the form
    /// <c>smd+{conid}+{"fields":["31","84","86"]}</c>, which is what IBKR expects
    /// to start streaming market data for a contract.
    /// </para>
    /// </summary>
    /// <param name="conid">The IBKR contract identifier.</param>
    /// <param name="fieldCodes">The array of numeric field code strings to subscribe to.</param>
    /// <returns>The complete subscribe message ready for transmission.</returns>
    private static string BuildSmdMessage(int conid, string[] fieldCodes) =>
        $"smd+{conid}+{JsonSerializer.Serialize(new { fields = fieldCodes })}";
}
