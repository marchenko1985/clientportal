# Doc Cleanup: XML Comments + README Reorganisation

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Inline Session.md, Signer.md, and Config.md into XML doc comments on their respective source files; move README.md to Web/README.md; delete the now-redundant markdown files.

**Architecture:** No runtime behaviour changes. Only documentation is affected. Every task ends with `dotnet build` to prove no compilation errors were introduced — `TreatWarningsAsErrors=true` means even a malformed XML comment attribute fails the build.

**Tech Stack:** .NET 10, C# XML documentation comments (`///`), `dotnet build`

---

## Background

- `TreatWarningsAsErrors=true` is set — a build failure means something broke.
- `dotnet run --project Web` uses `Web/Properties/launchSettings.json` (binds to `http://localhost:5000`).
- The three markdown files being deleted contain design/protocol docs that belong next to the code they describe.
- `Session.md` references `Signer.md` — both are being deleted, so cross-references become `<see cref="..."/>` instead.
- `Nginx.md` is referenced in `README.md` and `CLAUDE.md` but does not exist — this is a pre-existing broken link that gets cleaned up here.

---

### Task 1: Add XML doc comments to `Config.cs`

**Files:**
- Modify: `Web/Config.cs`

The file already has XML comments on `AccessTokenSecret`, `DhPrimeBytes`, and `PrivateSignatureBytes` — keep those unchanged. Add the class-level summary and comments on the six currently undocumented properties.

**Step 1: Replace the class declaration with a fully documented version**

Replace the existing `Config.cs` content with the following (keep existing `AccessTokenSecret`, `DhPrimeBytes`, `PrivateSignatureBytes` comments exactly as-is):

```csharp
using System.Diagnostics.CodeAnalysis;
using System.Numerics;
using System.Security.Cryptography;

namespace Web;

/// <summary>
/// Strongly-typed options class for the IBKR OAuth gateway, bound from the <c>Config</c>
/// JSON section in <c>appsettings.json</c> by the .NET options system.
/// </summary>
/// <remarks>
/// <para>
/// <b>Base64 byte array fields:</b> <see cref="AccessTokenSecret"/>, <see cref="DhPrimeBytes"/>,
/// and <see cref="PrivateSignatureBytes"/> are stored as base64 strings in JSON. The .NET
/// configuration binder automatically decodes them to <c>byte[]</c> — no manual conversion
/// is needed in application code.
/// </para>
/// <para>
/// <b>Computed fields:</b> <see cref="DhPrime"/> and <see cref="PrivateSignature"/> are set by
/// a <c>PostConfigure</c> call in <c>Program.cs</c> after binding. They are not read from
/// configuration and have <c>internal set</c> to prevent accidental assignment.
/// </para>
/// <para>
/// <b>Retrieving IBKR OAuth credentials:</b> visit
/// <c>https://ndcdyn.interactivebrokers.com/sso/Login?action=OAUTH&amp;RL=1&amp;ip2loc=US</c>
/// (the <c>action=OAUTH</c> query parameter is required; without it the login redirects to the
/// standard brokerage dashboard instead of the OAuth configuration page). Only one IBKR account
/// can hold an active OAuth session at a time. Separate credentials can be registered for a
/// paper-trading account.
/// </para>
/// <para>
/// Secrets are kept out of source control using environment-specific appsettings files
/// (<c>appsettings.Development.json</c>, <c>appsettings.Production.json</c>) or environment
/// variables using the double-underscore separator (e.g. <c>Config__ConsumerKey</c>).
/// </para>
/// </remarks>
[SuppressMessage("ReSharper", "UnusedAutoPropertyAccessor.Global")]
public class Config
{
    // Config-bound — .NET auto-decodes base64 strings to byte[]

    /// <summary>How often <c>POST /v1/api/tickle</c> is sent to keep the brokerage session alive.</summary>
    public required TimeSpan PingInterval { get; init; }

    /// <summary>How long to wait before restarting the OAuth handshake after any session failure.</summary>
    public required TimeSpan ReinitializeDelay { get; init; }

    /// <summary>OAuth realm string sent in every <c>Authorization</c> header. Typically <c>limited_poa</c>.</summary>
    public required string OAuthRealm { get; init; }

    /// <summary><c>User-Agent</c> header value sent on all outgoing IBKR API requests.</summary>
    public required string UserAgent { get; init; }

    /// <summary>OAuth consumer key assigned by IBKR when registering the OAuth application.</summary>
    public required string ConsumerKey { get; init; }

    /// <summary>OAuth access token assigned by IBKR.</summary>
    public required string AccessToken { get; init; }

    /// <summary>
    /// Decrypted access token secret bytes, base64-encoded in config.
    /// </summary>
    /// <remarks>
    /// Originally decrypted once from the RSA-PKCS1 ciphertext that IBKR issues, using private_encryption.pem.
    /// The ciphertext is the original AccessTokenSecret value from IBKR's oauth/live_session_token response.
    /// To reproduce (pipe the raw ciphertext bytes into openssl, then base64-encode the plaintext output):
    /// <code>
    /// echo "Fo6W5D1YCC9jfOOWhvRoKGv6Vz7xwY2AECGgVDv4Mwdw0XracNuFq8K5tTkBNM8T6a+k5MEQV/ApqWV/wCnVz/SHPI8Uger0KgMh0BmAtk3Q4/bH6KlmfrA6u2oXtFEo7bydwwEPNTUffvhxA/HH61I7TXDvUAhKR67vu2YOxXc+vTbB+SQUxu1bxf9ubgXEy2u7hSaCyn33mmYhVU9YTXbGmHhfOSEQG5YkhJhh5ibTgamu66dLLr4ChxH+Psx9G+yarGreBPKZOTRcM2PzKt5oKpP2Nkcj8sq0H4UIXp2hGVa7fciWkvQp75MCrvAdqB6Vg86ZFEG4mHw6WI3TmA==" \
    ///   | base64 -d \
    ///   | openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:pkcs1 -inkey private_encryption.pem \
    ///   | base64
    /// </code>
    /// </remarks>
    public required byte[] AccessTokenSecret { get; init; }

    /// <summary>
    /// Raw DH prime bytes, base64-encoded in config.
    /// </summary>
    /// <remarks>
    /// To regenerate from dhparam.pem:
    /// <code>
    /// openssl asn1parse -in dhparam.pem | grep INTEGER | head -n 1 | cut -d: -f4 | xxd -r -p | base64
    /// </code>
    /// </remarks>
    public required byte[] DhPrimeBytes { get; init; }

    /// <summary>
    /// PKCS#8 DER private signature key bytes, base64-encoded in config.
    /// </summary>
    /// <remarks>
    /// To regenerate from private_signature.pem (strips PEM headers — works because PEM is already base64 DER):
    /// <code>
    /// grep -v "^-----" private_signature.pem | tr -d '\n'
    /// </code>
    /// Imported at runtime via <see cref="System.Security.Cryptography.RSA.ImportPkcs8PrivateKey"/>.
    /// </remarks>
    public required byte[] PrivateSignatureBytes { get; init; }

    // Computed by PostConfigure — not bound from config

    /// <summary>
    /// DH prime <c>p</c> as a <see cref="BigInteger"/>, computed from <see cref="DhPrimeBytes"/>
    /// by <c>PostConfigure</c> in <c>Program.cs</c>. Not bound from configuration.
    /// </summary>
    public BigInteger DhPrime { get; internal set; }

    /// <summary>
    /// RSA private signing key imported from <see cref="PrivateSignatureBytes"/> by
    /// <c>PostConfigure</c> in <c>Program.cs</c> via
    /// <see cref="RSA.ImportPkcs8PrivateKey"/>. Not bound from configuration.
    /// </summary>
    public RSA PrivateSignature { get; internal set; } = null!;
}
```

**Step 2: Build**

```bash
cd /Users/mac/Desktop/ClientPortal && dotnet build
```

Expected: Build succeeded, 0 errors, 0 warnings.

**Step 3: Commit**

```bash
git add Web/Config.cs
git commit -m "docs: add XML doc comments to Config"
```

---

### Task 2: Add XML doc comments to `Signer.cs`

**Files:**
- Modify: `Web/Signer.cs`

The file has a brief one-line class summary. Replace the entire `Signer.cs` with a fully documented version.

**Step 1: Replace Signer.cs**

```csharp
using System.Globalization;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Options;

namespace Web;

/// <summary>
/// Produces OAuth authorization headers and the live session token for Interactive
/// Brokers' two-layer OAuth 1.0 scheme.
/// </summary>
/// <remarks>
/// <para>
/// <b>Layer 1 — Live session token (RSA-SHA256 + Diffie-Hellman):</b>
/// used once at startup for <c>POST /v1/api/oauth/live_session_token</c>.
/// The client generates a 256-bit DH private exponent <c>b</c>, computes the DH
/// challenge (<c>2^b mod p</c>), and signs an OAuth base string with the RSA private
/// key (PKCS#1 v1.5, SHA-256). IBKR-specific deviation from standard OAuth 1.0: the
/// access token secret encoded as lowercase hex is prepended to the base string before
/// signing. After the server responds with its DH public value <c>A</c>, the client
/// computes the shared secret (<c>A^b mod p</c>) and derives the live session token
/// via HMAC-SHA1 — see <see cref="ComputeLiveSessionToken"/>.
/// </para>
/// <para>
/// <b>Layer 2 — Per-request signing (HMAC-SHA256):</b>
/// used for every subsequent proxied API request. The live session token
/// (base64-decoded to raw bytes) is the HMAC key; the message is the standard
/// OAuth 1.0 base string with no secret prefix.
/// </para>
/// <para>
/// <b>Parameter sort order:</b> all OAuth parameter dictionaries must have keys in
/// ascending alphabetical order (RFC 5849 §3.4.1.3.2). The dictionaries are
/// initialised with keys already in order; no runtime sort is performed.
/// </para>
/// <para>
/// Reference: <see href="https://marchenko1985.github.io/ibkr-api-oauth/"/>
/// </para>
/// </remarks>
public class Signer
{
    private readonly Config _config;
    private readonly string _accessTokenSecretHex;

    public Signer(IOptions<Config> config)
    {
        _config = config.Value;
        _accessTokenSecretHex = Convert.ToHexString(_config.AccessTokenSecret).ToLowerInvariant();
    }

    /// <summary>
    /// Builds the <c>Authorization: OAuth …</c> header for the live session token
    /// handshake and returns the DH private exponent needed to complete the exchange.
    /// </summary>
    /// <returns>
    /// The Authorization header string and the DH private exponent <c>b</c>. The
    /// caller must pass <c>b</c> to <see cref="ComputeLiveSessionToken"/> together
    /// with the server's DH response value.
    /// </returns>
    /// <remarks>
    /// Signing algorithm: RSA-PKCS1-SHA256. The OAuth base string is prefixed with
    /// <see cref="Config.AccessTokenSecret"/> as lowercase hex before signing —
    /// this is an IBKR-specific extension to standard OAuth 1.0.
    /// </remarks>
    public (string AuthorizationHeader, BigInteger DhRandom) BuildLiveSessionTokenAuthorizationHeader(HttpMethod method, Uri requestUri)
    {
        var dhRandom = new BigInteger(RandomNumberGenerator.GetBytes(32), isUnsigned: true, isBigEndian: true);
        var challenge = BigInteger.ModPow(new BigInteger(2), dhRandom, _config.DhPrime).ToString("x", CultureInfo.InvariantCulture);

        // Keys must remain sorted alphabetically — required for OAuth base string construction (RFC 5849 §3.4.1.3.2).
        var oauthParams = new Dictionary<string, string>
        {
            ["diffie_hellman_challenge"] = challenge,
            ["oauth_consumer_key"] = _config.ConsumerKey,
            ["oauth_nonce"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
            ["oauth_signature_method"] = "RSA-SHA256",
            ["oauth_timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ["oauth_token"] = _config.AccessToken
        };

        var baseString = _accessTokenSecretHex + BuildBaseString(method, requestUri.ToString(), oauthParams);
        var signature = _config.PrivateSignature.SignData(Encoding.UTF8.GetBytes(baseString), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var headerParams = new Dictionary<string, string>(oauthParams)
        {
            ["oauth_signature"] = Uri.EscapeDataString(Convert.ToBase64String(signature))
        };

        return (BuildAuthorizationHeader(headerParams), dhRandom);
    }

    /// <summary>
    /// Builds the <c>Authorization: OAuth …</c> header for a standard signed API request.
    /// </summary>
    /// <param name="method">HTTP method.</param>
    /// <param name="requestUri">Full request URI including scheme and host.</param>
    /// <param name="liveSessionToken">
    /// Base64-encoded live session token from the most recent DH exchange
    /// (see <see cref="ComputeLiveSessionToken"/>).
    /// </param>
    /// <remarks>
    /// Signing algorithm: HMAC-SHA256. The live session token is base64-decoded to
    /// obtain the raw key bytes. The base string follows standard OAuth 1.0 format
    /// with no secret prefix (unlike the live session token request).
    /// </remarks>
    public string BuildApiAuthorizationHeader(HttpMethod method, Uri requestUri, string liveSessionToken)
    {
        // Keys must remain sorted alphabetically — required for OAuth base string construction (RFC 5849 §3.4.1.3.2).
        var oauthParams = new Dictionary<string, string>
        {
            ["oauth_consumer_key"] = _config.ConsumerKey,
            ["oauth_nonce"] = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(),
            ["oauth_signature_method"] = "HMAC-SHA256",
            ["oauth_timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(CultureInfo.InvariantCulture),
            ["oauth_token"] = _config.AccessToken
        };

        var baseString = BuildBaseString(method, requestUri.ToString(), oauthParams);
        var signature = HMACSHA256.HashData(Convert.FromBase64String(liveSessionToken), Encoding.UTF8.GetBytes(baseString));

        var headerParams = new Dictionary<string, string>(oauthParams)
        {
            ["oauth_signature"] = Uri.EscapeDataString(Convert.ToBase64String(signature))
        };

        return BuildAuthorizationHeader(headerParams);
    }

    /// <summary>
    /// Derives the live session token from the completed Diffie-Hellman exchange.
    /// </summary>
    /// <param name="dhResponse">
    /// The server's DH public value <c>A</c>, parsed from the hex string in the
    /// <c>diffie_hellman_response</c> field of the server's response body.
    /// </param>
    /// <param name="dhRandom">
    /// The client's DH private exponent <c>b</c> returned by
    /// <see cref="BuildLiveSessionTokenAuthorizationHeader"/>.
    /// </param>
    /// <returns>Base64-encoded live session token.</returns>
    /// <remarks>
    /// <para>
    /// Computation: <c>token = Base64(HMAC-SHA1(sharedSecretBytes, accessTokenSecretBytes))</c>
    /// where <c>sharedSecretBytes</c> is the shared secret <c>A^b mod p</c> serialised
    /// as signed big-endian bytes.
    /// </para>
    /// <para>
    /// The signed serialisation — prepend <c>0x00</c> if the high bit of the leading
    /// byte is set — matches Java's <c>BigInteger.toByteArray()</c> semantics.
    /// IBKR's server-side implementation uses Java, so this byte layout is required
    /// for the HMAC inputs to agree. <see cref="BigInteger.ToByteArray"/> with
    /// <c>isUnsigned: false, isBigEndian: true</c> produces exactly this layout.
    /// </para>
    /// </remarks>
    public string ComputeLiveSessionToken(BigInteger dhResponse, BigInteger dhRandom)
    {
        var sharedSecret = BigInteger.ModPow(dhResponse, dhRandom, _config.DhPrime);
        // ToByteArray(isUnsigned: false) produces signed big-endian, prepending 0x00 when the
        // high bit is set — matching Java's BigInteger.toByteArray() as required by the IBKR protocol.
        var sharedSecretBytes = sharedSecret.ToByteArray(isUnsigned: false, isBigEndian: true);

        return Convert.ToBase64String(HMACSHA1.HashData(sharedSecretBytes, _config.AccessTokenSecret));
    }

    private static string BuildBaseString(HttpMethod method, string url, IReadOnlyDictionary<string, string> parameters)
    {
        var pairs = string.Join("&", parameters.Select(pair => $"{pair.Key}={pair.Value}"));
        return $"{method.Method}&{Uri.EscapeDataString(url)}&{Uri.EscapeDataString(pairs)}";
    }

    private string BuildAuthorizationHeader(IReadOnlyDictionary<string, string> parameters)
    {
        var pairs = string.Join(", ", parameters.Select(pair => $"{pair.Key}=\"{pair.Value}\""));
        return $"OAuth realm=\"{_config.OAuthRealm}\", {pairs}";
    }
}
```

**Step 2: Build**

```bash
cd /Users/mac/Desktop/ClientPortal && dotnet build
```

Expected: Build succeeded, 0 errors, 0 warnings.

**Step 3: Commit**

```bash
git add Web/Signer.cs
git commit -m "docs: add XML doc comments to Signer"
```

---

### Task 3: Add XML doc comments to `Session.cs`

**Files:**
- Modify: `Web/Session.cs`

The `Session` class has no XML comments on the class, its properties, or its methods. The `TickleResponse`, `Server`, and `AuthenticationStatus` records already have property-level comments — leave those untouched.

**Step 1: Replace Session.cs**

```csharp
using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Numerics;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Web;

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
        var req = new HttpRequestMessage(method, uri);
        req.Content = content;
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

[SuppressMessage("ReSharper", "UnusedMember.Global")]
[SuppressMessage("ReSharper", "AutoPropertyCanBeMadeGetOnly.Global")]
public record Server
{
    [JsonPropertyName("authStatus")]
    public AuthenticationStatus AuthenticationStatus { get; init; } = new();
}

[SuppressMessage("ReSharper", "UnusedMember.Global")]
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
```

**Step 2: Build**

```bash
cd /Users/mac/Desktop/ClientPortal && dotnet build
```

Expected: Build succeeded, 0 errors, 0 warnings.

**Step 3: Commit**

```bash
git add Web/Session.cs
git commit -m "docs: add XML doc comments to Session"
```

---

### Task 4: Move README.md to Web/README.md and update CLAUDE.md

**Files:**
- Move: `README.md` → `Web/README.md`
- Modify: `CLAUDE.md`

**Step 1: Move README.md**

```bash
mv /Users/mac/Desktop/ClientPortal/README.md /Users/mac/Desktop/ClientPortal/Web/README.md
```

**Step 2: Update links in Web/README.md**

The following links need updating (file is now in `Web/`, not repo root):

| Old link | New link | Reason |
|---|---|---|
| `[Config.md](Config.md)` | remove / replace with prose | file is being deleted |
| `[Session.md](Session.md)` | remove / replace with prose | file is being deleted |
| `[Signer.md](Signer.md)` | remove / replace with prose | file is being deleted |
| `[Nginx.md](Nginx.md)` | remove | file never existed |
| `[Test.md](Test.md)` | `[Test.md](../Test.md)` | file stays at repo root |

Replace the "Reference docs" table at the bottom of `Web/README.md` with:

```markdown
## Reference docs

Key implementation details live as XML doc comments directly on the source files:
`Config.cs`, `Session.cs`, `Signer.cs`.

See [`../Test.md`](../Test.md) for curl and WebSocket smoke test commands.
```

In the body of `Web/README.md`, replace the inline references:
- `See [Config.md](Config.md) for the full reference:` → `See `Config.cs` for the full reference:`
- `See [Test.md](Test.md) for curl and WebSocket smoke test commands.` → `See [Test.md](../Test.md) for curl and WebSocket smoke test commands.`
- `See [Nginx.md](Nginx.md) for:` → `See [Deployment.md](../Deployment.md) for:`

**Step 3: Update CLAUDE.md**

In `CLAUDE.md`, replace the "Reference docs" section at the bottom:

Old:
```markdown
- `Config.md` — all `appsettings.json` keys, base64 extraction commands, appsettings layering strategy
- `Signer.md` — IBKR two-layer OAuth protocol, the DH exchange, before/after comparison
- `Session.md` — session state machine, public properties, keep-alive details
- `Nginx.md` — nginx site config, systemd unit, forwarded headers rationale
```

New:
```markdown
- `Web/README.md` — Web project overview, proxied routes, running instructions
- `Test.md` — curl and WebSocket smoke test commands
- Implementation details (session lifecycle, OAuth signing, config fields) live as XML doc comments in `Web/Session.cs`, `Web/Signer.cs`, `Web/Config.cs`
```

Also update the inline reference in CLAUDE.md:
- `See \`Test.md\` for curl and WebSocket smoke test commands.` — no change needed (Test.md stays at root, CLAUDE.md stays at root)
- `See \`Config.md\` for the one-time extraction commands` → `See \`Web/Config.cs\` (the \`DhPrimeBytes\`, \`AccessTokenSecret\`, \`PrivateSignatureBytes\` XML comments) for the one-time extraction commands`

**Step 4: Build**

```bash
cd /Users/mac/Desktop/ClientPortal && dotnet build
```

Expected: Build succeeded, 0 errors, 0 warnings.

**Step 5: Commit**

```bash
git add Web/README.md CLAUDE.md
git commit -m "docs: move README to Web/, update CLAUDE.md references"
```

---

### Task 5: Delete Config.md, Session.md, Signer.md

**Files:**
- Delete: `Config.md`, `Session.md`, `Signer.md`

**Step 1: Delete the files**

```bash
cd /Users/mac/Desktop/ClientPortal && rm Config.md Session.md Signer.md
```

**Step 2: Build (confirms no .csproj or build target referenced these files)**

```bash
dotnet build
```

Expected: Build succeeded, 0 errors, 0 warnings.

**Step 3: Commit**

```bash
git add -A
git commit -m "docs: delete Config.md, Session.md, Signer.md (content moved to XML comments)"
```

---

## Done

After all tasks:
- `Web/Config.cs`, `Web/Session.cs`, `Web/Signer.cs` are fully documented with XML comments
- `Config.md`, `Session.md`, `Signer.md` are deleted
- `Web/README.md` is the Web project README with updated links
- `CLAUDE.md` references updated to point to source files and `Web/README.md`
- Build passes with zero warnings
