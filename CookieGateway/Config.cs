using System.Diagnostics;

namespace CookieGateway;

/// <summary>
/// Strongly-typed options class for the IBKR cookie-based gateway, bound from the <c>Config</c>
/// JSON section in <c>appsettings.json</c> by the .NET options system.
/// </summary>
/// <remarks>
/// <para>
/// Credentials (<see cref="Username"/>, <see cref="Password"/>) are kept out of source control
/// using environment-specific appsettings files (<c>appsettings.Development.json</c>,
/// <c>appsettings.Production.json</c>) or environment variables using the double-underscore
/// separator (e.g. <c>Config__Username</c>, <c>Config__Password</c>).
/// </para>
/// </remarks>
public class Config
{
    /// <summary>How often <c>POST /v1/api/tickle</c> is sent to keep the brokerage session alive.</summary>
    public required TimeSpan PingInterval { get; init; }

    /// <summary>How long to wait before restarting the login sequence after any session failure.</summary>
    public required TimeSpan ReinitializeDelay { get; init; }

    /// <summary><c>User-Agent</c> header value sent on all outgoing IBKR API requests.</summary>
    public required string UserAgent { get; init; }

    /// <summary>IBKR account username. Set in environment-specific appsettings or via <c>Config__Username</c> env var.</summary>
    public required string Username { get; init; }

    /// <summary>IBKR account password. Set in environment-specific appsettings or via <c>Config__Password</c> env var.</summary>
    [DebuggerBrowsable(DebuggerBrowsableState.Never)]
    public required string Password { get; init; }
}
