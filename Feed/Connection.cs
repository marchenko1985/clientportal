using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;
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
///       <see cref="Config.PingInterval"/> cadence to keep the connection alive.
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
///       capped at 600 s), then reconnects. After 3 consecutive failures the snapshot
///       cache is cleared to prevent new clients from receiving stale data.
///     </description>
///   </item>
/// </list>
/// </para>
/// </summary>
public class Connection(Snapshots snapshots, IOptions<Config> options, ILogger<Connection> logger) : BackgroundService
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
    /// same connection. SendAsync of  ClientWebSocket is not thread-safe
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
    /// Current lifecycle phase of the upstream connection.
    /// Values: <c>"disconnected"</c>, <c>"connecting"</c>, <c>"connected"</c>, <c>"authenticated"</c>.
    /// </summary>
    private volatile string _state = "disconnected";

    /// <summary>Gets the current lifecycle phase string of the upstream connection.</summary>
    public string State => _state;

    /// <summary>
    /// Count of consecutive reconnect attempts since the last successful session.
    /// Reset to 0 on each successful <see cref="ConnectAndRunAsync"/> completion.
    /// </summary>
    private int _reconnectAttempts;

    /// <summary>Gets the number of consecutive reconnect failures since the last successful connection.</summary>
    public int ReconnectAttempts => Volatile.Read(ref _reconnectAttempts);

    /// <summary>
    /// Unbounded channel used to broadcast connection-lifecycle events
    /// (<c>connected</c>, <c>authenticated</c>) to <see cref="Hub"/> so that all
    /// browser clients can be notified in real time.
    /// </summary>
    private readonly Channel<(string Topic, bool Data)> _systemMessages =
        Channel.CreateUnbounded<(string, bool)>(new UnboundedChannelOptions { SingleReader = true });

    /// <summary>
    /// Reader end of the system-events channel. <see cref="Hub"/> consumes this to
    /// broadcast upstream state changes to all connected browser clients.
    /// </summary>
    public ChannelReader<(string Topic, bool Data)> SystemMessages => _systemMessages.Reader;

    private void PublishSystem(string topic, bool data) =>
        _systemMessages.Writer.TryWrite((topic, data));

    /// <summary>
    /// Records a request to receive market data for the specified contract.
    ///
    /// <para>
    /// If this conid already has an active upstream subscription (field set may have
    /// changed), an <c>umd+{conid}+{}</c> unsubscribe is sent first to clear the old
    /// subscription before the new <c>smd</c> with the updated field list. The
    /// semaphore serialises these two fire-and-forget sends in FIFO order so
    /// <c>umd</c> always precedes <c>smd</c> on the wire.
    /// </para>
    ///
    /// <para>
    /// If the upstream connection is currently authenticated, the subscribe message
    /// is sent immediately. Otherwise the entry is queued in
    /// <c>_pendingSubscriptions</c> and will be flushed by <see cref="FlushPendingAsync"/>
    /// once authentication is confirmed.
    /// </para>
    /// </summary>
    /// <param name="conid">The IBKR contract identifier (e.g. <c>265598</c> for AAPL).</param>
    /// <param name="fieldCodes">
    /// The full field union to request from IBKR for this conid.
    /// </param>
    public void Subscribe(int conid, string[] fieldCodes)
    {
        var alreadySubscribed = false;
        _pendingSubscriptions.AddOrUpdate(conid, fieldCodes, (_, _) => { alreadySubscribed = true; return fieldCodes; });
        if (IsAuthenticated)
        {
            if (alreadySubscribed) _ = SendAsync($"umd+{conid}+{{}}");
            _ = SendAsync(BuildSmdMessage(conid, fieldCodes));
        }
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
    /// </summary>
    /// <param name="conid">The IBKR contract identifier to stop streaming.</param>
    public void Unsubscribe(int conid)
    {
        _pendingSubscriptions.TryRemove(conid, out _);
        if (IsAuthenticated) _ = SendAsync($"umd+{conid}+{{}}");
    }

    /// <summary>
    /// Main background-service loop. Repeatedly calls <see cref="ConnectAndRunAsync"/>
    /// with exponential back-off between attempts until the application stops.
    /// After 3 consecutive failures the snapshot cache is cleared to prevent new
    /// clients from seeing data that may be hours old.
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
                Volatile.Write(ref _reconnectAttempts, 0);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested) { break; }
            catch (Exception ex) { logger.LogError(ex, "Connection error"); }

            if (stoppingToken.IsCancellationRequested) break;
            attempt++;
            Volatile.Write(ref _reconnectAttempts, attempt);
            if (attempt == 3)
            {
                logger.LogWarning("3 consecutive upstream failures — clearing stale snapshot cache");
                snapshots.ClearAll();
            }
            var delaySec = (int)Math.Min(30 * Math.Pow(2, attempt - 1), 600);
            if (logger.IsEnabled(LogLevel.Information)) logger.LogInformation("Reconnecting in {Delay}s (attempt {Attempt})", delaySec, attempt);
            try { await Task.Delay(TimeSpan.FromSeconds(delaySec), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    /// <summary>
    /// Opens a fresh WebSocket connection to IBKR, sends the initial heartbeat,
    /// then runs the heartbeat and receive loops concurrently until one of them
    /// terminates. Publishes <c>connected</c> and <c>authenticated</c> system events
    /// to <see cref="SystemMessages"/> as lifecycle phases change.
    /// </summary>
    private async Task ConnectAndRunAsync(CancellationToken ct)
    {
        _ws = new ClientWebSocket();
        try
        {
            _state = "connecting";
            if (logger.IsEnabled(LogLevel.Information)) logger.LogInformation("Connecting to {Uri}", options.Value.BaseAddress);
            await _ws.ConnectAsync(options.Value.BaseAddress, ct);
            _state = "connected";
            PublishSystem("connected", true);
            if (logger.IsEnabled(LogLevel.Information)) logger.LogInformation("Connected — waiting for sts");

            SetAuthenticated(false);

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
            PublishSystem("authenticated", false);
            PublishSystem("connected", false);
            _state = "disconnected";
            SetAuthenticated(false);
            if (_ws.State == WebSocketState.Open)
            {
                try
                {
                    await _ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "closing", CancellationToken.None);
                }
                catch
                {
                    // noop
                }
            }
            _ws.Dispose();
            _ws = null;
        }
    }

    /// <summary>
    /// Sends a <c>tic</c> keepalive frame to IBKR at
    /// <see cref="Config.PingInterval"/> cadence for as long as the connection is active.
    /// </summary>
    private async Task HeartbeatAsync(CancellationToken ct)
    {
        using var timer = new PeriodicTimer(options.Value.PingInterval);
        while (await timer.WaitForNextTickAsync(ct))
        {
            await SendAsync("tic", ct);
        }
    }

    /// <summary>
    /// Continuously reads WebSocket frames from the upstream IBKR connection,
    /// reassembles fragmented messages, and passes each complete UTF-8 text
    /// message to <see cref="OnMessage"/>.
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
                if (result.MessageType == WebSocketMessageType.Close) { logger.LogInformation("Close frame received"); return; }
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
    ///       subscriptions. A <c>authenticated</c> system event is published.
    ///     </description>
    ///   </item>
    ///   <item>
    ///     <term><c>smd+{conid}</c></term>
    ///     <description>
    ///       Market-data tick for a contract. Every JSON key whose name is a pure
    ///       integer string (e.g. <c>"31"</c>, <c>"84"</c>) is treated as an IBKR
    ///       field code. The raw string value is written to <see cref="Snapshots"/>.
    ///     </description>
    ///   </item>
    /// </list>
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
                    if (logger.IsEnabled(LogLevel.Information)) logger.LogInformation("sts authenticated={Auth}", authenticated);
                    PublishSystem("authenticated", authenticated);
                    _state = authenticated ? "authenticated" : "connected";
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
                {
                    if (int.TryParse(key, out _) && value is JsonValue jv && jv.TryGetValue<string>(out var raw))
                    {
                        snapshots.Write(conid, key, raw, ticks);
                    }
                }
            }
        }
        catch (Exception ex) { logger.LogWarning(ex, "Message parse error"); }
    }

    /// <summary>
    /// Sends a fresh <c>smd+{conid}+{...}</c> subscribe message for every entry
    /// currently in <c>_pendingSubscriptions</c>.
    ///
    /// <para>
    /// This is called once per connection, immediately after IBKR confirms
    /// authentication via a <c>sts</c> message.
    /// </para>
    /// </summary>
    private async Task FlushPendingAsync(CancellationToken ct)
    {
        foreach (var (conid, fields) in _pendingSubscriptions)
        {
            await SendAsync(BuildSmdMessage(conid, fields), ct);
        }
    }

    /// <summary>
    /// Serialises and sends a UTF-8 text frame over the active WebSocket connection,
    /// acquiring <c>_sendLock</c> first to guarantee that at most one send is
    /// in-flight at a time.
    /// </summary>
    /// <param name="message">The text payload to send.</param>
    /// <param name="ct">Cancellation token; passed to both the semaphore wait and the send.</param>
    private async Task SendAsync(string message, CancellationToken ct = default)
    {
        await _sendLock.WaitAsync(ct);
        try
        {
            if (_ws?.State == WebSocketState.Open)
            {
                await _ws.SendAsync(Encoding.UTF8.GetBytes(message), WebSocketMessageType.Text, true, ct);
            }
        }
        catch (Exception ex)
        {
            if (logger.IsEnabled(LogLevel.Warning)) logger.LogWarning(ex, "Send failed: {Msg}", message);
        }
        finally { _sendLock.Release(); }
    }

    /// <summary>
    /// Builds the IBKR wire-format subscribe message for the given contract and
    /// field codes.
    ///
    /// <para>
    /// The resulting string has the form
    /// <c>smd+{conid}+{"fields":["31","84","86"]}</c>.
    /// </para>
    /// </summary>
    /// <param name="conid">The IBKR contract identifier.</param>
    /// <param name="fieldCodes">The array of numeric field code strings to subscribe to.</param>
    /// <returns>The complete subscription message ready for transmission.</returns>
    private static string BuildSmdMessage(int conid, string[] fieldCodes) => $"smd+{conid}+{JsonSerializer.Serialize(new { fields = fieldCodes })}";
}
