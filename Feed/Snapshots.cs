using System.Collections.Concurrent;
using System.Threading.Channels;

namespace Feed;

/// <summary>
/// Thread-safe store of the latest known value for every (conid, field) pair received
/// from the upstream IBKR WebSocket connection.
///
/// <para>
/// <b>Role in the system:</b> <see cref="Connection"/> writes raw market-data values
/// here as they arrive from IBKR. <see cref="Hub"/> reads current values from
/// this store when flushing event-driven batch updates collected from the change channel.
/// </para>
///
/// <para>
/// <b>Why deduplication matters:</b> IBKR often re-sends the same field value across
/// consecutive ticks (e.g. a bid price that has not moved). Without deduplication every
/// flush cycle would include those unchanged fields, inflating downstream traffic and
/// causing browser clients to process redundant updates. <see cref="Write"/> therefore
/// leaves the stored timestamp unchanged when the incoming value is identical to what is
/// already stored, so no duplicate change event is published to the flush pipeline.
/// </para>
///
/// <para>
/// <b>Value representation:</b> IBKR delivers all field values as raw strings
/// (e.g. <c>"182.45"</c>, <c>"2.5K"</c>, <c>"N/A"</c>). This store preserves them
/// verbatim — no parsing or normalisation is performed.
/// </para>
/// </summary>
public class Snapshots
{
    public readonly record struct MarketTick(int Conid, string Field, long Ticks);

    /// <summary>
    /// Backing store keyed by <c>(conid, field)</c> tuple.
    /// Each entry holds the latest raw string value and the <see cref="DateTime.Ticks"/>
    /// timestamp at which that value was last <i>changed</i> (not merely received).
    /// <see cref="ConcurrentDictionary{TKey,TValue}"/> is used so that
    /// <see cref="Connection"/> and <see cref="Hub"/> can read/write
    /// concurrently without explicit locking.
    /// </summary>
    private readonly ConcurrentDictionary<(int Conid, string Field), (string Value, long Ticks)> _store = new();
    private readonly Channel<MarketTick> _changes = Channel.CreateUnbounded<MarketTick>(
        new UnboundedChannelOptions
        {
            SingleReader = true,
            SingleWriter = false
        });

    /// <summary>
    /// Writes a new raw value for the specified contract and field.
    ///
    /// <para>
    /// <b>Deduplication behaviour:</b> if the incoming <paramref name="value"/> is
    /// identical to the value already stored for <c>(conid, field)</c> the existing
    /// entry — including its timestamp — is left untouched. This means
    /// no new change event is published for unchanged values,
    /// avoiding redundant downstream traffic.
    /// </para>
    ///
    /// <para>
    /// The method is lock-free: it delegates to
    /// <see cref="ConcurrentDictionary{TKey,TValue}.AddOrUpdate"/> which provides
    /// atomic compare-and-update semantics.
    /// </para>
    /// </summary>
    /// <param name="conid">
    /// The IBKR contract identifier (e.g. <c>265598</c> for AAPL).
    /// </param>
    /// <param name="field">
    /// The numeric field code as a string (e.g. <c>"31"</c> for last price,
    /// <c>"84"</c> for bid). Using the raw IBKR string avoids an unnecessary
    /// int-parse step and keeps the key space identical to the wire format.
    /// </param>
    /// <param name="value">
    /// The raw field value exactly as received from IBKR (e.g. <c>"182.45"</c>,
    /// <c>"2.5K"</c>, <c>"N/A"</c>).
    /// </param>
    /// <param name="ticks">
    /// A monotonic timestamp (typically <see cref="DateTime.UtcNow"/>.<see cref="DateTime.Ticks"/>)
    /// recorded when this value was received. Only stored when the value actually
    /// changes, so it accurately reflects the last <i>change</i> time.
    /// </param>
    public void Write(int conid, string field, string value, long ticks)
    {
        var key = (conid, field);
        while (true)
        {
            if (_store.TryGetValue(key, out var existing))
            {
                if (existing.Value == value) return;
                if (!_store.TryUpdate(key, (value, ticks), existing)) continue;
            }
            else if (!_store.TryAdd(key, (value, ticks)))
            {
                continue;
            }

            _changes.Writer.TryWrite(new MarketTick(conid, field, ticks));
            return;
        }
    }

    public ChannelReader<MarketTick> ReadChanges() => _changes.Reader;

    public void RemoveConid(int conid)
    {
        foreach (var key in _store.Keys)
        {
            if (key.Conid == conid)
            {
                _store.TryRemove(key, out _);
            }
        }
    }

    /// <summary>
    /// Returns the current (latest) value for each of the requested fields for a
    /// given contract, regardless of when each value was last updated.
    ///
    /// <para>
    /// This is used when a browser client first subscribes to a contract: sending the
    /// full current snapshot immediately gives the client a consistent starting state
    /// before event-driven incremental updates begin.
    /// </para>
    ///
    /// <para>
    /// Fields that have never been received from IBKR are silently omitted from the
    /// result; the caller should treat a missing key as "not yet available".
    /// </para>
    /// </summary>
    /// <param name="conid">The IBKR contract identifier.</param>
    /// <param name="fields">
    /// The set of field codes to retrieve (e.g. <c>["31", "84", "86"]</c>).
    /// Typically the union of fields all current subscribers to this contract have
    /// requested, as tracked by <c>Subscriptions</c>.
    /// </param>
    /// <returns>
    /// A read-only dictionary mapping each field code that is present in the store to
    /// its latest raw value. The dictionary is a snapshot; later writes to the store
    /// do not affect the returned object.
    /// </returns>
    public IReadOnlyDictionary<string, string> GetSnapshot(int conid, string[] fields)
    {
        var result = new Dictionary<string, string>();
        foreach (var field in fields)
        {
            if (_store.TryGetValue((conid, field), out var entry))
            {
                result[field] = entry.Value;
            }
        }
        return result;
    }

}
