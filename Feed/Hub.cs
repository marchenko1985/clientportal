using System.Collections.Concurrent;
using System.Net.WebSockets;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Threading.Channels;
using Microsoft.Extensions.Options;

namespace Feed;

/// <summary>
/// Background service that accepts browser WebSocket connections and fans out
/// market-data updates to interested clients.
///
/// <para>
/// <b>Protocol — client → server:</b>
/// <list type="bullet">
///   <item><description><c>smd+{conid}+{"fields":[...]}</c> — subscribe to market data for a contract.</description></item>
///   <item><description><c>umd+{conid}+{}</c> — unsubscribe from a contract.</description></item>
/// </list>
/// </para>
///
/// <para>
/// <b>Protocol — server → client:</b> all outbound messages use a typed
/// <c>{"topic":"…","data":…}</c> envelope.
/// <list type="bullet">
///   <item><description><c>{"topic":"connected","data":true/false}</c> — upstream connection state change.</description></item>
///   <item><description><c>{"topic":"authenticated","data":true/false}</c> — upstream authentication state change.</description></item>
///   <item><description><c>{"topic":"batch","data":[{conid, field:val, …}]}</c> — market-data tick batch for subscribed conids.</description></item>
/// </list>
/// </para>
///
/// <para>
/// System events (<c>connected</c>, <c>authenticated</c>) are read from
/// <see cref="Connection.SystemMessages"/> and broadcast to all connected clients.
/// New clients are immediately greeted with the current upstream state so they are
/// never left in the dark.
/// </para>
/// </summary>
public class Hub(Connection connection, Subscriptions subscriptions, Snapshots snapshots, IOptions<Config> options, ILogger<Hub> logger) : BackgroundService
{
    private readonly TimeSpan _batchInterval = options.Value.BatchInterval;

    private readonly ConcurrentDictionary<ConnectedClient, byte> _clients = new();
    private readonly ConcurrentDictionary<int, ConcurrentDictionary<ConnectedClient, byte>> _clientsByConid = new();

    private readonly Lock _pendingChangesLock = new();
    private Dictionary<int, HashSet<string>> _pendingChanges = [];

    private long _activeClientSubscriptions;

    /// <summary>Number of browser clients currently connected over WebSocket.</summary>
    public int ConnectedClients => _clients.Count;

    /// <summary>Total number of active (conid, client) subscription pairs.</summary>
    public int ActiveSubscriptions => (int)Interlocked.Read(ref _activeClientSubscriptions);

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        using var workerCts = CancellationTokenSource.CreateLinkedTokenSource(stoppingToken);
        var collectTask = CollectChangesAsync(workerCts.Token);
        var systemTask = CollectSystemMessagesAsync(workerCts.Token);

        using var timer = new PeriodicTimer(_batchInterval);
        try
        {
            while (await timer.WaitForNextTickAsync(stoppingToken))
            {
                FlushPendingBatches();
            }
        }
        catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
        {
        }
        finally
        {
            await workerCts.CancelAsync();
            try { await collectTask; } catch (OperationCanceledException) { }
            try { await systemTask; } catch (OperationCanceledException) { }
        }
    }

    public async Task AddClientAsync(WebSocket ws, CancellationToken ct, CancellationToken stoppingToken)
    {
        var client = new ConnectedClient(ws);
        _clients.TryAdd(client, 0);
        if (logger.IsEnabled(LogLevel.Information)) logger.LogInformation("Client connected (total: {Count})", _clients.Count);

        // Greet new client with current upstream state.
        client.Enqueue(Envelope("connected", connection.State != "disconnected"));
        client.Enqueue(Envelope("authenticated", connection.IsAuthenticated));

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        try
        {
            await Task.WhenAny(
                ReceiveLoopAsync(client, cts.Token),
                client.RunSendLoopAsync(cts.Token));
        }
        finally
        {
            await cts.CancelAsync();
            client.Complete();
            _clients.TryRemove(client, out _);

            foreach (var conid in client.Conids.Keys.ToList())
            {
                RemoveClientSubscription(client, conid, unsubscribeUpstream: !stoppingToken.IsCancellationRequested);
            }

            if (logger.IsEnabled(LogLevel.Information)) logger.LogInformation("Client disconnected (total: {Count})", _clients.Count);
        }
    }

    private async Task CollectChangesAsync(CancellationToken ct)
    {
        var reader = snapshots.ReadChanges();
        await foreach (var tick in reader.ReadAllAsync(ct))
        {
            lock (_pendingChangesLock)
            {
                if (!_pendingChanges.TryGetValue(tick.Conid, out var fields))
                {
                    fields = [];
                    _pendingChanges[tick.Conid] = fields;
                }

                fields.Add(tick.Field);
            }
        }
    }

    /// <summary>
    /// Reads system events from <see cref="Connection.SystemMessages"/> and broadcasts
    /// each as a typed envelope to all currently connected browser clients.
    /// </summary>
    private async Task CollectSystemMessagesAsync(CancellationToken ct)
    {
        await foreach (var (topic, data) in connection.SystemMessages.ReadAllAsync(ct))
        {
            var msg = Envelope(topic, data);
            foreach (var (client, _) in _clients)
                client.Enqueue(msg);
        }
    }

    private void FlushPendingBatches()
    {
        Dictionary<int, HashSet<string>> pending;
        lock (_pendingChangesLock)
        {
            if (_pendingChanges.Count == 0) return;
            pending = _pendingChanges;
            _pendingChanges = [];
        }

        var batches = new Dictionary<ConnectedClient, JsonArray>();

        foreach (var (conid, changedFields) in pending)
        {
            if (!_clientsByConid.TryGetValue(conid, out var interestedClients)) continue;

            foreach (var (client, _) in interestedClients)
            {
                if (!client.Conids.TryGetValue(conid, out var clientFields)) continue;

                var relevantFields = clientFields.Where(changedFields.Contains).ToArray();
                if (relevantFields.Length == 0) continue;

                var snapshot = snapshots.GetSnapshot(conid, relevantFields);
                if (snapshot.Count == 0) continue;

                if (!batches.TryGetValue(client, out var batch))
                {
                    batch = [];
                    batches[client] = batch;
                }

                var obj = new JsonObject { ["conid"] = conid };
                foreach (var (field, value) in snapshot)
                {
                    obj[field] = JsonValue.Create(value);
                }
                batch.Add(obj);
            }
        }

        if (batches.Count == 0) return;

        var totalObjects = 0L;
        foreach (var (client, batch) in batches)
        {
            totalObjects += batch.Count;
            client.Enqueue(Envelope("batch", batch));
        }

        if (logger.IsEnabled(LogLevel.Debug))
            logger.LogDebug("Flushed {ClientBatches} client batches ({Objects} objects)", batches.Count, totalObjects);
    }

    private async Task ReceiveLoopAsync(ConnectedClient client, CancellationToken ct)
    {
        var buffer = new byte[4_096];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                using var ms = new MemoryStream();
                WebSocketReceiveResult result;
                do
                {
                    result = await client.Ws.ReceiveAsync(buffer, ct);
                    if (result.MessageType == WebSocketMessageType.Close)
                    {
                        await client.Ws.CloseAsync(WebSocketCloseStatus.NormalClosure, "Bye", CancellationToken.None);
                        return;
                    }
                    ms.Write(buffer, 0, result.Count);
                } while (!result.EndOfMessage);

                HandleMessage(client, Encoding.UTF8.GetString(ms.ToArray()));
            }
        }
        catch (OperationCanceledException) { }
        catch (WebSocketException) { }
    }

    private void HandleMessage(ConnectedClient client, string text)
    {
        try
        {
            if (text.StartsWith("smd+"))
            {
                var secondPlus = text.IndexOf('+', 4);
                if (secondPlus < 0 || !int.TryParse(text.AsSpan(4, secondPlus - 4), out var conid)) return;

                var fields = JsonNode.Parse(text[(secondPlus + 1)..])?["fields"]?.AsArray()
                    .Select(n => n?.GetValue<string>()).Where(s => s != null).Select(s => s!).ToArray() ?? [];
                if (fields.Length == 0) return;

                if (client.Conids.ContainsKey(conid))
                {
                    RemoveClientSubscription(client, conid, unsubscribeUpstream: true);
                }

                var upstreamFields = subscriptions.Subscribe(conid, client.Id, fields);
                if (upstreamFields != null) connection.Subscribe(conid, upstreamFields);

                var snap = snapshots.GetSnapshot(conid, fields);
                if (snap.Count > 0)
                {
                    var obj = new JsonObject { ["conid"] = conid };
                    foreach (var (f, v) in snap) obj[f] = JsonValue.Create(v);
                    client.Enqueue(Envelope("batch", new JsonArray(obj)));
                }

                AddClientSubscription(client, conid, fields);
                if (logger.IsEnabled(LogLevel.Information)) logger.LogInformation("Subscribed conid {Conid}", conid);
            }
            else if (text.StartsWith("umd+"))
            {
                var secondPlus = text.IndexOf('+', 4);
                if (secondPlus < 0 || !int.TryParse(text.AsSpan(4, secondPlus - 4), out var conid)) return;

                RemoveClientSubscription(client, conid, unsubscribeUpstream: true);
                if (logger.IsEnabled(LogLevel.Information)) logger.LogInformation("Unsubscribed conid {Conid}", conid);
            }
        }
        catch (Exception ex)
        {
            if (logger.IsEnabled(LogLevel.Warning)) logger.LogWarning(ex, "Failed to handle: {Text}", text);
        }
    }

    private void AddClientSubscription(ConnectedClient client, int conid, string[] fields)
    {
        client.Conids[conid] = fields;
        var clients = _clientsByConid.GetOrAdd(conid, _ => new ConcurrentDictionary<ConnectedClient, byte>());
        clients.TryAdd(client, 0);
        Interlocked.Increment(ref _activeClientSubscriptions);
    }

    private void RemoveClientSubscription(ConnectedClient client, int conid, bool unsubscribeUpstream)
    {
        if (!client.Conids.TryRemove(conid, out _)) return;

        if (_clientsByConid.TryGetValue(conid, out var clients))
        {
            clients.TryRemove(client, out _);
            if (clients.IsEmpty)
            {
                _clientsByConid.TryRemove(conid, out _);
            }
        }

        Interlocked.Decrement(ref _activeClientSubscriptions);

        if (unsubscribeUpstream)
        {
            subscriptions.Unsubscribe(conid, client.Id);
        }
    }

    /// <summary>Serialises a typed <c>{topic, data}</c> envelope to JSON.</summary>
    private static string Envelope(string topic, object data) =>
        JsonSerializer.Serialize(new { topic, data });

    private sealed class ConnectedClient(WebSocket ws)
    {
        public readonly Guid Id = Guid.NewGuid();
        public readonly WebSocket Ws = ws;
        public readonly ConcurrentDictionary<int, string[]> Conids = new();

        private readonly Channel<string> _sendChannel = Channel.CreateBounded<string>(
            new BoundedChannelOptions(1_000)
            {
                FullMode = BoundedChannelFullMode.DropOldest
            });

        public void Enqueue(string msg) => _sendChannel.Writer.TryWrite(msg);
        public void Complete() => _sendChannel.Writer.TryComplete();

        public async Task RunSendLoopAsync(CancellationToken ct)
        {
            try
            {
                await foreach (var msg in _sendChannel.Reader.ReadAllAsync(ct))
                {
                    if (Ws.State != WebSocketState.Open) break;
                    await Ws.SendAsync(Encoding.UTF8.GetBytes(msg), WebSocketMessageType.Text, true, ct);
                }
            }
            catch (OperationCanceledException) { }
            catch (WebSocketException) { }
        }
    }
}
