using System.Net;
using System.Text.Json.Serialization;
using CookieGateway.Extensions;
using CookieGateway.Login;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace CookieGateway;

/// <summary>
/// Background service that owns the IBKR brokerage session for the lifetime of the
/// application, authenticating with username/password via SRP and keeping the session
/// alive with periodic pings.
/// </summary>
/// <remarks>
/// <para>
/// <b>Why this exists:</b> the IBKR API requires an authenticated browser session
/// (via cookies) before any request can be made. This service performs a full SRP
/// login on startup, stores the resulting cookies in <see cref="SessionCookie"/>,
/// and keeps the session alive with <c>POST /v1/api/tickle</c> at regular intervals.
/// IBKR silently expires sessions that go quiet. Set-Cookie headers on every tickle
/// response are merged into <see cref="SessionCookie"/> so the cookie string stays
/// current throughout the session lifetime.
/// </para>
/// <para>
/// <b>State machine:</b>
/// <list type="number">
///   <item><description>
///     <c>Initializing</c> — <see cref="InitializeAsync"/> runs the three-phase
///     startup: SRP login → SSODH session init → first tickle.
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
/// <b>Public state consumed by <c>Program.cs</c>:</b> <see cref="SessionCookie"/>
/// is injected as the <c>Cookie</c> header on every proxied HTTP and WebSocket
/// request forwarded through YARP.
/// </para>
/// </remarks>
public class Session(IHttpClientFactory httpClientFactory, IOptions<Config> config, ILogger<Session> logger) : BackgroundService
{
    private static readonly Uri LoginBaseAddress = new("https://ndcdyn.interactivebrokers.com");

    private readonly HttpClient _httpClient = httpClientFactory.CreateClient(nameof(Session));

    /// <summary>
    /// The response from the most recent <c>POST /v1/api/tickle</c> call.
    /// <see langword="null"/> until the first successful <see cref="PingAsync"/> call.
    /// </summary>
    public TickleResponse? LastTickleResponse { get; private set; }

    /// <summary>
    /// The accumulated session cookie string established during SRP login and kept
    /// current by merging <c>Set-Cookie</c> headers from subsequent API responses.
    /// Injected as <c>Cookie: &lt;value&gt;</c> on every proxied request via the YARP
    /// transform in <c>Program.cs</c>. <see langword="null"/> until the first successful
    /// <see cref="InitializeAsync"/> completes.
    /// </summary>
    public string? SessionCookie { get; private set; }

    /// <summary>UTC timestamp of the most recent successful tickle. <see langword="null"/> until the first ping.</summary>
    public DateTime? LastPingTime { get; private set; }

    /// <summary>
    /// Current lifecycle phase: <c>"Initializing"</c>, <c>"Ready"</c>,
    /// <c>"Reinitializing"</c>, or <c>"Stopping"</c>. Exposed on the
    /// <c>/session</c> JSON endpoint.
    /// </summary>
    public string State { get; private set; } = "Initializing";

    /// <summary>
    /// <see langword="true"/> when <see cref="State"/> is <c>"Ready"</c>, a session
    /// cookie exists, and the last tickle response confirms
    /// <c>authenticated=true</c>. Used by <see cref="HealthCheck"/> to report
    /// application health.
    /// </summary>
    public bool Healthy => State == "Ready" && SessionCookie != null && LastTickleResponse?.Server.AuthenticationStatus.Authenticated == true;

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
    /// Runs the three-phase IBKR session startup sequence.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Phase 1 — SRP Login:</b> creates a temporary <see cref="HttpClient"/> with a
    /// <see cref="CookieContainer"/> pointing at <c>ndcdyn.interactivebrokers.com</c> and
    /// performs the full 7-step SRP-6 authentication flow (INIT → COMPLETEAUTH → Dispatcher).
    /// The resulting cookies are stored in <see cref="SessionCookie"/>.
    /// </para>
    /// <para>
    /// <b>Phase 2 — SSODH init:</b> calls <c>POST /v1/api/iserver/auth/ssodh/init</c>
    /// with <c>publish=true, compete=true</c> to activate the brokerage session.
    /// <c>compete=true</c> allows taking over from an existing active session on the same account.
    /// </para>
    /// <para>
    /// <b>Phase 3 — First tickle:</b> calls <see cref="PingAsync"/> immediately to confirm
    /// the session is live and populate <see cref="LastTickleResponse"/> before
    /// <see cref="State"/> is set to <c>"Ready"</c>.
    /// </para>
    /// </remarks>
    private async Task InitializeAsync(CancellationToken ct)
    {
        // Phase 1: SRP login via a temporary local HttpClient.
        // This client uses a CookieContainer and auto-redirects so that all cookies
        // set during the login flow are accumulated automatically.
        using var loginHandler = new HttpClientHandler
        {
            CookieContainer = new CookieContainer(),
            UseCookies = true,
            AllowAutoRedirect = true,
            AutomaticDecompression = DecompressionMethods.All
        };
        using var loginClient = new HttpClient(loginHandler)
        {
            BaseAddress = LoginBaseAddress,
            Timeout = TimeSpan.FromSeconds(15)
        };
        loginClient.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", config.Value.UserAgent);

        // Step 1: GET /sso/Login — retrieves initial cookies (JSESSIONID) and page params.
        var loginResp = await loginClient.GetAsync("/sso/Login?loginType=2&forwardTo=22&clt=0&RL=1&ip2loc=US", ct);
        loginResp.EnsureSuccessStatusCode();
        var jsessionId = loginHandler.CookieContainer.GetAllCookies().FirstOrDefault(c => c.Name == "JSESSIONID")?.Value;
        ArgumentException.ThrowIfNullOrEmpty(jsessionId);

        // Step 2: Build SRP client and generate key pair.
        var srp = new SprClient(config.Value.Username, config.Value.Password);
        var (privateKey, publicKey) = srp.GenerateKeyPair();

        // Step 3: POST /sso/Authenticator (ACTION=INIT) — server sends B, salt, RSA public key.
        var initResp = await loginClient.PostAsFormAsync("/sso/Authenticator", new
        {
            ACTION = "INIT",
            USER = config.Value.Username,
            A = SprClient.Pad(publicKey.ToUnsignedHexString()),
            RESP_TYPE = "JSON",
            LOGIN_TYPE = "2",
            SERVICE = "AM.LOGIN"
        }, ct);
        initResp.EnsureSuccessStatusCode();

        var initJson = await initResp.Content.ReadFromJsonAsync<System.Text.Json.Nodes.JsonNode>(ct);
        ArgumentNullException.ThrowIfNull(initJson);
        var error = initJson["error"]?.ToString();
        if (!string.IsNullOrEmpty(error)) throw new InvalidOperationException($"SRP INIT error: {error}");

        // If server returns non-default SRP params, rebuild client and retry INIT.
        var serverHash = initJson["hash"]?.ToString() ?? SprClient.DefaultHash;
        var serverN = initJson["N"]?.ToString() ?? SprClient.DefaultN;
        var serverG = initJson["g"]?.ToString() ?? SprClient.DefaultG;
        var serverProto = initJson["proto"]?.ToString() ?? SprClient.DefaultProto;

        if (serverHash != SprClient.DefaultHash || serverN != SprClient.DefaultN || serverG != SprClient.DefaultG || serverProto != SprClient.DefaultProto)
        {
            srp = new SprClient(config.Value.Username, config.Value.Password, serverHash, serverN, serverG, serverProto);
            (privateKey, publicKey) = srp.GenerateKeyPair();

            var retryResp = await loginClient.PostAsFormAsync("/sso/Authenticator", new
            {
                ACTION = "INIT",
                USER = config.Value.Username,
                A = SprClient.Pad(publicKey.ToUnsignedHexString()),
                RESP_TYPE = "JSON",
                LOGIN_TYPE = "2",
                SERVICE = "AM.LOGIN"
            }, ct);
            retryResp.EnsureSuccessStatusCode();
            initJson = await retryResp.Content.ReadFromJsonAsync<System.Text.Json.Nodes.JsonNode>(ct);
            ArgumentNullException.ThrowIfNull(initJson);
            error = initJson["error"]?.ToString();
            if (!string.IsNullOrEmpty(error)) throw new InvalidOperationException($"SRP INIT retry error: {error}");
        }

        var bHex = initJson["B"]?.ToString();
        var salt = initJson["s"]?.ToString();
        var rsaPublicKeyHex = initJson["rsapub"]?.ToString();
        ArgumentException.ThrowIfNullOrEmpty(bHex);
        ArgumentException.ThrowIfNullOrEmpty(salt);
        ArgumentException.ThrowIfNullOrEmpty(rsaPublicKeyHex);

        // If lp=false, password must be truncated to 8 characters before SRP math.
        if (initJson["lp"]?.GetValue<bool>() == false)
            srp.SetPassword(config.Value.Password[..Math.Min(8, config.Value.Password.Length)]);

        // Step 4: Compute SRP values.
        var serverPublicKey = bHex.ToUnsignedBigInteger();
        var scrambler = srp.CalculateScrambling(publicKey, serverPublicKey);
        var sharedSecret = srp.CalculateSharedSecret(serverPublicKey, salt, scrambler, privateKey);
        var sessionKey = srp.DeriveSessionKey(sharedSecret);
        var clientProof = srp.CalculateClientProof(salt, publicKey, serverPublicKey, sessionKey);
        var expectedServerProof = srp.ComputeExpectedServerProof(publicKey, clientProof, sessionKey);
        var encryptedSessionKey = RsaUtils.EncryptSessionKey(rsaPublicKeyHex, sessionKey);
        var xyzab = srp.CalculateSessionKey(bHex, sessionKey);

        // Step 5: POST /sso/Authenticator (ACTION=COMPLETEAUTH) — verify server proof M2.
        var completeResp = await loginClient.PostAsFormAsync("/sso/Authenticator", new
        {
            ACTION = "COMPLETEAUTH",
            USER = config.Value.Username,
            M1 = SprClient.Pad(clientProof.ToUnsignedHexString()),
            EKX = encryptedSessionKey,
            RESP_TYPE = "JSON",
            VERSION = "1",
            LOGIN_TYPE = "2"
        }, ct);
        completeResp.EnsureSuccessStatusCode();

        var completeJson = await completeResp.Content.ReadFromJsonAsync<System.Text.Json.Nodes.JsonNode>(ct);
        ArgumentNullException.ThrowIfNull(completeJson);
        error = completeJson["error"]?.ToString();
        if (!string.IsNullOrEmpty(error)) throw new InvalidOperationException($"SRP COMPLETEAUTH error: {error}");

        var m2 = completeJson["M2"]?.ToString();
        ArgumentException.ThrowIfNullOrEmpty(m2);
        if (!m2.ToUnsignedBigInteger().Equals(expectedServerProof))
            throw new InvalidOperationException("SRP server proof mismatch — shared secret does not match.");

        if (completeJson["reached_max_login"]?.GetValue<bool>() == true)
            throw new InvalidOperationException("Reached max login attempts.");

        if (completeJson["sftypes"]?.AsArray().Count > 0)
            throw new InvalidOperationException("Two-factor authentication required — not supported.");

        // Step 6: Set XYZAB cookies required before Dispatcher POST.
        loginHandler.CookieContainer.Add(LoginBaseAddress, new Cookie("XYZAB_AM.LOGIN", xyzab));
        loginHandler.CookieContainer.Add(LoginBaseAddress, new Cookie("XYZAB", xyzab));

        // Step 7: POST /sso/Dispatcher — follows redirects, accumulates all session cookies.
        var dispatchResp = await loginClient.PostAsFormAsync("/sso/Dispatcher", new { loginType = "2", forwardTo = "22" }, ct);
        dispatchResp.EnsureSuccessStatusCode();

        var cookies = loginHandler.CookieContainer.GetCookieHeader(LoginBaseAddress);
        ArgumentException.ThrowIfNullOrEmpty(cookies, "Login produced no cookies — authentication may have failed silently.");
        SessionCookie = cookies;
        logger.LogInformation("SRP login succeeded, session cookies established.");

        // Phase 2: SSODH init — activates the brokerage session on api.ibkr.com.
        using var ssodhReq = CreateCookieRequest(HttpMethod.Post, "/v1/api/iserver/auth/ssodh/init",
            JsonContent.Create(new { publish = true, compete = true }));
        using var ssodhRes = await _httpClient.SendAsync(ssodhReq, ct);
        ssodhRes.EnsureSuccessStatusCode();
        MergeResponseCookies(ssodhRes);

        // Phase 3: First tickle confirms the session is live.
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
        using var tickleReq = CreateCookieRequest(HttpMethod.Post, "/v1/api/tickle", null);
        using var tickleRes = await _httpClient.SendAsync(tickleReq, ct);
        tickleRes.EnsureSuccessStatusCode();
        MergeResponseCookies(tickleRes);
        LastTickleResponse = await tickleRes.Content.ReadFromJsonAsync<TickleResponse>(ct);
        ArgumentNullException.ThrowIfNull(LastTickleResponse, "Tickle response deserialization returned null.");
        LastPingTime = DateTime.UtcNow;
        if (LastTickleResponse?.Server.AuthenticationStatus.Authenticated == false)
        {
            throw new InvalidOperationException($"Tickle response indicates not authenticated: {LastTickleResponse.Server.AuthenticationStatus.Message ?? LastTickleResponse.Server.AuthenticationStatus.Fail ?? "no message"}");
        }
    }

    /// <summary>
    /// Builds an <see cref="HttpRequestMessage"/> with the current <see cref="SessionCookie"/>
    /// injected as the <c>Cookie</c> header. Used for all post-login requests to
    /// <c>api.ibkr.com</c> made by this service (SSODH init, tickle).
    /// </summary>
    private HttpRequestMessage CreateCookieRequest(HttpMethod method, string path, HttpContent? content)
    {
        var req = new HttpRequestMessage(method, new Uri(_httpClient.BaseAddress!, path)) { Content = content };
        if (!string.IsNullOrEmpty(SessionCookie))
            req.Headers.TryAddWithoutValidation("Cookie", SessionCookie);
        return req;
    }

    /// <summary>
    /// Merges <c>Set-Cookie</c> headers from an IBKR API response into <see cref="SessionCookie"/>.
    /// Called after every API response so that the cookie string stays current and the
    /// YARP transform always injects up-to-date cookies on proxied requests.
    /// </summary>
    private void MergeResponseCookies(HttpResponseMessage response)
    {
        if (!response.Headers.TryGetValues("Set-Cookie", out var setCookies)) return;

        var cookies = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (!string.IsNullOrEmpty(SessionCookie))
        {
            foreach (var part in SessionCookie.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                var eq = part.IndexOf('=');
                if (eq > 0) cookies[part[..eq]] = part[(eq + 1)..];
            }
        }

        var changed = false;
        foreach (var header in setCookies)
        {
            var nameValue = header.Split(';')[0].Trim();
            var eq = nameValue.IndexOf('=');
            if (eq <= 0) continue;
            var name = nameValue[..eq].Trim();
            var value = nameValue[(eq + 1)..].Trim();
            if (cookies.TryGetValue(name, out var existing) && existing == value) continue;
            cookies[name] = value;
            changed = true;
        }

        if (changed)
            SessionCookie = string.Join("; ", cookies.Select(kv => $"{kv.Key}={kv.Value}"));
    }
}

/// <summary>Health check that reflects <see cref="Session.Healthy"/>.</summary>
public class HealthCheck(Session session) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext context, CancellationToken ct = default) => Task.FromResult(session.Healthy ? HealthCheckResult.Healthy() : HealthCheckResult.Unhealthy(session.State));
}

/// <summary>Response from <c>POST /v1/api/tickle</c>.</summary>
public record TickleResponse
{
    /// <summary>Session token of the contract. Retained for compatibility with the tickle response shape.</summary>
    public string Session { get; init; } = string.Empty;

    /// <summary>Number of milliseconds until the current SSO session expires.</summary>
    [JsonPropertyName("ssoExpires")]
    public int SingleSignOnExpires { get; init; }

    /// <summary>Internal use only.</summary>
    public int UserId { get; init; }

    /// <summary>Brokerage server details returned by tickle.</summary>
    [JsonPropertyName("iserver")]
    public Server Server { get; init; } = new();
}

/// <summary>Brokerage server info wrapper returned inside tickle responses.</summary>
public record Server
{
    [JsonPropertyName("authStatus")]
    public AuthenticationStatus AuthenticationStatus { get; init; } = new();
}

/// <summary>Authentication status of the brokerage session, as reported by tickle.</summary>
public record AuthenticationStatus
{
    /// <summary>Returns whether your brokerage session is authenticated or not.</summary>
    public bool Authenticated { get; init; }

    /// <summary>
    /// Returns whether your brokerage session is fully established and ready to handle requests.
    /// Set to true when the login message is received from underlying brokerage infrastructure,
    /// indicating authentication is complete and account information is loaded.
    /// </summary>
    public bool Established { get; init; }

    /// <summary>Returns whether you have a competing brokerage session in another connection.</summary>
    public bool Competing { get; init; }

    /// <summary>Returns whether you are connected to the gateway or not.</summary>
    public bool Connected { get; init; }

    /// <summary>A message about your authenticated status, if any.</summary>
    public string? Message { get; init; }

    /// <summary>Returns the reason for failing to retrieve authentication status.</summary>
    public string? Fail { get; init; }
}
