using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Numerics;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Gateway;

/// <summary>
/// Background service that owns the IBKR brokerage session for the lifetime of the
/// application, maintaining a valid live session token and keeping the session alive
/// with periodic pings.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists:</b> the IBKR API requires a live session token before any
/// request can be made. The token is derived via a Diffie-Hellman key exchange at
/// startup and must be refreshed after any failure. Once established, the session must
/// be kept alive with <c>POST /v1/api/tickle</c> at regular intervals — IBKR silently
/// expires sessions that go quiet. This service owns that entire lifecycle so the rest
/// of the application can read <see cref="LiveSessionToken"/> without thinking about
/// authentication state.
/// </para>
/// <para>
/// <b>State machine:</b>
/// <list type="number">
///   <item><description>
///     <c>Initializing</c> — <see cref="InitializeAsync"/> runs the three-step startup
///     sequence: live session token handshake → SSO session init → first tickle.
///   </description></item>
///   <item><description>
///     <c>Ready</c> — <see cref="KeepAliveAsync"/> loops, calling <see cref="PingAsync"/>
///     every <see cref="Config.PingInterval"/>.
///   </description></item>
///   <item><description>
///     <c>Reinitializing</c> — any exception from either phase is caught, logged, and
///     followed by a <see cref="Config.ReinitializeDelay"/> wait before the entire
///     sequence restarts from step 1.
///   </description></item>
///   <item><description>
///     <c>Stopping</c> — <see cref="OperationCanceledException"/> on the application's
///     cancellation token exits the loop cleanly.
///   </description></item>
/// </list>
/// </para>
/// <para>
/// <b>Public state consumed by <c>Program.cs</c>:</b> <see cref="LiveSessionToken"/>
/// is used as the HMAC-SHA256 signing key for every proxied HTTP request.
/// <see cref="LastTickleResponse"/> provides the WebSocket session cookie value
/// (<c>Cookie: api=&lt;session&gt;</c>) required for WebSocket upgrades through YARP.
/// </para>
/// </remarks>
public class Session(IHttpClientFactory httpClientFactory, Signer signer, IOptions<Config> config, ILogger<Session> logger) : BackgroundService
{
    private readonly HttpClient _httpClient = httpClientFactory.CreateClient(nameof(Session));

    /// <summary>
    /// The response from the most recent <c>POST /v1/api/tickle</c> call.
    /// <see cref="TickleResponse.Session"/> contains the WebSocket cookie value used by
    /// the YARP transform for WebSocket upgrades (<c>Cookie: api=&lt;value&gt;</c>).
    /// <see langword="null"/> until the first successful <see cref="PingAsync"/> call.
    /// </summary>
    public TickleResponse? LastTickleResponse { get; private set; }

    /// <summary>
    /// Base64-encoded live session token derived from the most recent DH exchange.
    /// Used as the HMAC-SHA256 key when signing proxied API requests via
    /// <see cref="Signer.BuildApiAuthorizationHeader"/>. <see langword="null"/> until
    /// the first successful <see cref="InitializeAsync"/> completes.
    /// </summary>
    public string? LiveSessionToken { get; private set; }

    /// <summary>UTC timestamp of the most recent successful tickle. <see langword="null"/> until the first ping.</summary>
    public DateTime? LastPingTime { get; private set; }

    /// <summary>
    /// Current lifecycle phase: <c>"Initializing"</c>, <c>"Ready"</c>,
    /// <c>"Reinitializing"</c>, or <c>"Stopping"</c>. Exposed on the
    /// <c>/session</c> JSON endpoint.
    /// </summary>
    public string State { get; private set; } = "Initializing";

    /// <summary>
    /// <see langword="true"/> when <see cref="State"/> is <c>"Ready"</c>, a live
    /// session token exists, and the last tickle response confirms
    /// <c>authenticated=true</c>. Used by <see cref="HealthCheck"/> to report
    /// application health.
    /// </summary>
    public bool Healthy => State == "Ready" && LiveSessionToken != null && LastTickleResponse?.Server.AuthenticationStatus.Authenticated == true;

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                State = "Initializing";
                await InitializeAsync(stoppingToken);
                State = "Ready";
                logger.LogInformation("Interactive Brokers session initialized, keep-alive started.");

                await KeepAliveAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                State = "Stopping";
                break;
            }
            catch (Exception ex)
            {
                State = "Reinitializing";
                logger.LogWarning(ex, "Session loop failed, will reinitialize.");
            }

            try
            {
                await Task.Delay(config.Value.ReinitializeDelay, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
        }
    }

    /// <summary>
    /// Runs the three-step IBKR session startup sequence.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Step 1 — Live session token:</b> sends <c>POST /v1/api/oauth/live_session_token</c>
    /// with an RSA-SHA256 signed OAuth header (including a Diffie-Hellman challenge).
    /// The server responds with a DH public value as a hex string. The hex may have an
    /// odd number of characters (a leading nibble is sometimes stripped by the server);
    /// it is normalised to even length before being parsed to a <see cref="BigInteger"/>.
    /// Both the server's DH value and the client's private exponent are passed to
    /// <see cref="Signer.ComputeLiveSessionToken"/> to derive <see cref="LiveSessionToken"/>.
    /// </para>
    /// <para>
    /// <b>Step 2 — SSO session:</b> sends <c>POST /v1/api/iserver/auth/ssodh/init</c>
    /// with <c>publish=true, compete=true</c>. This activates the brokerage session.
    /// <c>compete=true</c> allows taking over from an existing active session on the same account.
    /// </para>
    /// <para>
    /// <b>Step 3 — First tickle:</b> calls <see cref="PingAsync"/> immediately to confirm
    /// the session is live and populate <see cref="LastTickleResponse"/> before
    /// <see cref="State"/> is set to <c>"Ready"</c>.
    /// </para>
    /// </remarks>
    private async Task InitializeAsync(CancellationToken ct)
    {
        var uri = new Uri(_httpClient.BaseAddress!, "/v1/api/oauth/live_session_token");
        var (authHeader, dhRandom) = signer.BuildLiveSessionTokenAuthorizationHeader(HttpMethod.Post, uri);

        using var req = new HttpRequestMessage(HttpMethod.Post, uri);
        req.Headers.Authorization = AuthenticationHeaderValue.Parse(authHeader);

        using var response = await _httpClient.SendAsync(req, ct);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadFromJsonAsync<JsonNode>(ct);
        var dhResponseHex = json?["diffie_hellman_response"]?.ToString() ?? throw new InvalidOperationException("Missing diffie_hellman_response");
        // Normalize to even length — Convert.FromHexString requires it, and DH values can have a leading nibble stripped.
        var dhResponse = new BigInteger(Convert.FromHexString(dhResponseHex.Length % 2 == 0 ? dhResponseHex : "0" + dhResponseHex), isUnsigned: true, isBigEndian: true);
        LiveSessionToken = signer.ComputeLiveSessionToken(dhResponse, dhRandom);

        using var ssodhReq = CreateSignedRequest(HttpMethod.Post, "/v1/api/iserver/auth/ssodh/init", JsonContent.Create(new { publish = true, compete = true }));
        using var ssodhRes = await _httpClient.SendAsync(ssodhReq, ct);
        ssodhRes.EnsureSuccessStatusCode();

        await PingAsync(ct);
    }

    private async Task KeepAliveAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await Task.Delay(config.Value.PingInterval, ct);
            await PingAsync(ct);
        }
    }

    /// <summary>
    /// Sends <c>POST /v1/api/tickle</c>, stores the response in
    /// <see cref="LastTickleResponse"/>, and throws if the brokerage session reports
    /// it is no longer authenticated.
    /// </summary>
    /// <remarks>
    /// IBKR can return HTTP 200 with <c>iserver.authStatus.authenticated=false</c>
    /// when the brokerage session has silently expired — a successful HTTP status code
    /// does not guarantee the session is still valid. When this occurs,
    /// <see cref="InvalidOperationException"/> is thrown so the outer loop in
    /// <see cref="ExecuteAsync"/> treats it like any other failure and restarts
    /// the full initialization sequence.
    /// </remarks>
    private async Task PingAsync(CancellationToken ct)
    {
        using var tickleReq = CreateSignedRequest(HttpMethod.Post, "/v1/api/tickle", null);
        using var tickleRes = await _httpClient.SendAsync(tickleReq, ct);
        tickleRes.EnsureSuccessStatusCode();
        LastTickleResponse = await tickleRes.Content.ReadFromJsonAsync<TickleResponse>(ct);
        LastPingTime = DateTime.UtcNow;
        if (LastTickleResponse?.Server.AuthenticationStatus.Authenticated == false)
        {
            throw new InvalidOperationException($"Tickle response indicates not authenticated: {LastTickleResponse.Server.AuthenticationStatus.Message ?? LastTickleResponse.Server.AuthenticationStatus.Fail ?? "no message"}");
        }
    }

    /// <summary>
    /// Builds an <see cref="HttpRequestMessage"/> with a full HMAC-SHA256
    /// <c>Authorization: OAuth …</c> header signed with <see cref="LiveSessionToken"/>.
    /// Used for all post-handshake requests (SSO session init, tickle).
    /// </summary>
    private HttpRequestMessage CreateSignedRequest(HttpMethod method, string path, HttpContent? content)
    {
        var uri = new Uri(_httpClient.BaseAddress!, path);
        var req = new HttpRequestMessage(method, uri) { Content = content };
        req.Headers.Authorization = AuthenticationHeaderValue.Parse(signer.BuildApiAuthorizationHeader(method, uri, LiveSessionToken!));
        return req;
    }
}

public class HealthCheck(Session session) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default) => Task.FromResult(session.Healthy ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy(session.State));
}

public record TickleResponse
{
    /// <summary>
    /// Returns the session token of the contract.
    /// </summary>
    public string Session { get; init; } = string.Empty;

    /// <summary>
    /// Returns the number of milliseconds until the current sso session expires.
    /// </summary>
    [JsonPropertyName("ssoExpires")]
    public int SingleSignOnExpires { get; init; }

    /// <summary>
    /// Internal use only
    /// </summary>
    public int UserId { get; init; }

    [JsonPropertyName("iserver")]
    public Server Server { get; init; } = new();
}

[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
public record Server
{
    [JsonPropertyName("authStatus")]
    public AuthenticationStatus AuthenticationStatus { get; init; } = new();
}

[SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
public record AuthenticationStatus
{
    /// <summary>
    /// Returns whether your brokerage session is authenticated or not.
    /// </summary>
    public bool Authenticated { get; init; }

    /// <summary>
    /// Returns whether your brokerage session is fully established and ready to handle requests.
    /// Set to true when the login message is received from underlying brokerage infrastructure, indicating authentication is complete and account information is loaded.
    /// </summary>
    public bool Established { get; init; }

    /// <summary>
    /// Returns whether you have a competing brokerage session in another connection.
    /// </summary>
    public bool Competing { get; init; }

    /// <summary>
    /// Returns whether you are connected to the gateway or not.
    /// </summary>
    public bool Connected { get; init; }

    /// <summary>
    /// A message about your authenticated status, if any.
    /// </summary>
    public string? Message { get; init; }

    /// <summary>
    /// Returns the reason for failing to retrieve authentication status.
    /// </summary>
    public string? Fail { get; init; }
}
