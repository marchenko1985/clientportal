using System.Diagnostics.CodeAnalysis;
using System.Net.Http.Headers;
using System.Numerics;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization;
using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;

namespace Web;

public class Session(IHttpClientFactory httpClientFactory, Signer signer, IOptions<Config> config, ILogger<Session> logger) : BackgroundService
{
    private readonly HttpClient _httpClient = httpClientFactory.CreateClient(nameof(Session));

    public TickleResponse? LastTickleResponse { get; private set; }
    public string? LiveSessionToken { get; private set; }
    public DateTime? LastPingTime { get; private set; }
    public string State { get; private set; } = "Initializing";

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

    private async Task PingAsync(CancellationToken ct)
    {
        using var tickleReq = CreateSignedRequest(HttpMethod.Post, "/v1/api/tickle", null);
        using var tickleRes = await _httpClient.SendAsync(tickleReq, ct);
        tickleRes.EnsureSuccessStatusCode();
        LastTickleResponse = await tickleRes.Content.ReadFromJsonAsync<TickleResponse>(ct);
        LastPingTime = DateTime.UtcNow;
    }

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
