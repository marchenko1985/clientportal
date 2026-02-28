namespace Feed;

public record Config
{
    public required Uri BaseAddress { get; init; }
    public required TimeSpan PingInterval { get; init; }
    public required TimeSpan BatchInterval { get; init; }
    public required TimeSpan UnsubscribeDelay { get; init; }
}
