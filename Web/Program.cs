using System.Net.Http.Headers;
using System.Numerics;
using System.Security.Cryptography;
using Microsoft.Extensions.Compliance.Classification;
using Microsoft.Extensions.Compliance.Redaction;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;
using Web;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false); // do not tell we are written in dotnet

var allowedOrigins = builder.Configuration.GetSection("AllowedOrigins").Get<string[]>();
ArgumentNullException.ThrowIfNull(allowedOrigins);

builder.Services.AddOptions<Config>().Bind(builder.Configuration.GetSection(nameof(Config))).PostConfigure(config =>
{
    config.DhPrime = new BigInteger(config.DhPrimeBytes, isUnsigned: true, isBigEndian: true);
    config.PrivateSignature = RSA.Create();
    config.PrivateSignature.ImportPkcs8PrivateKey(config.PrivateSignatureBytes, out _);
}).ValidateOnStart();

builder.Services.AddCors(options => options.AddPolicy("AllowedOrigins", policy => policy.WithOrigins(allowedOrigins).AllowAnyHeader().AllowAnyMethod().AllowCredentials()));
builder.Services.AddHealthChecks().AddCheck<HealthCheck>(nameof(HealthCheck));

builder.Services.AddSingleton<Signer>();
builder.Services.AddRedaction(redactionBuilder => redactionBuilder.SetRedactor<NullRedactor>(DataClassificationSet.FromDataClassification(DataClassification.Unknown)));
builder.Services.AddHttpClient(nameof(Session), (provider, client) =>
{
    var config = provider.GetRequiredService<IOptions<Config>>().Value;
    client.BaseAddress = new Uri(builder.Configuration["ReverseProxy:Clusters:InteractiveBrokers:Destinations:Primary:Address"] ?? throw new InvalidOperationException("Missing InteractiveBrokers base address"));
    client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", config.UserAgent);
}).AddExtendedHttpClientLogging(o =>
{
    // Bind scalar options from config (e.g. LogBody, RequestPathParameterRedactionMode).
    builder.Configuration.GetSection("HttpClientLogging").Bind(o);
    // ISet and IDictionary properties cannot be bound from JSON, so they are configured here.
    o.RequestBodyContentTypes.Add("application/json");
    o.ResponseBodyContentTypes.Add("application/json");
    o.ResponseBodyContentTypes.Add("text/html");
    o.ResponseBodyContentTypes.Add("text/plain");
    foreach (var header in builder.Configuration.GetSection("HttpClientLogging:AllowedRequestHeaders").Get<string[]>() ?? [])
    {
        o.RequestHeadersDataClasses[header] = DataClassification.Unknown;
    }
    foreach (var header in builder.Configuration.GetSection("HttpClientLogging:AllowedResponseHeaders").Get<string[]>() ?? [])
    {
        o.ResponseHeadersDataClasses[header] = DataClassification.Unknown;
    }
}).AddStandardResilienceHandler(builder.Configuration.GetSection(nameof(HttpStandardResilienceOptions)));
builder.Services.AddSingleton<Session>().AddHostedService(p => p.GetRequiredService<Session>());

builder.Services.AddReverseProxy().LoadFromConfig(builder.Configuration.GetSection("ReverseProxy")).AddTransforms(ctx =>
{
    ctx.UseDefaultForwarders = false;
    var signer = ctx.Services.GetRequiredService<Signer>();
    var session = ctx.Services.GetRequiredService<Session>();
    var config = ctx.Services.GetRequiredService<IOptions<Config>>().Value;

    ctx.AddRequestTransform(transform =>
    {
        var requestUri = new Uri($"{transform.DestinationPrefix}{transform.HttpContext.Request.Path}{transform.HttpContext.Request.QueryString}");
        // var isWebSocket = transform.HttpContext.WebSockets.IsWebSocketRequest; // this one does not work
        var isWebSocket = transform.HttpContext.Request.Headers.Upgrade.ToString().Equals("websocket", StringComparison.OrdinalIgnoreCase);

        transform.ProxyRequest.Headers.TryAddWithoutValidation("User-Agent", config.UserAgent);

        if (isWebSocket)
        {
            // if (!allowedOrigins.Contains(ctx.Request.Headers.Origin.ToString())) { ctx.Response.StatusCode = 403; return; }
            transform.ProxyRequest.Headers.Authorization = null;
            transform.ProxyRequest.Headers.Remove("Cookie");
            transform.ProxyRequest.Headers.TryAddWithoutValidation("Cookie", $"api={session.LastTickleResponse?.Session}");
            transform.ProxyRequest.RequestUri = new Uri($"{transform.DestinationPrefix}{transform.HttpContext.Request.Path}?oauth_token={Uri.EscapeDataString(config.AccessToken)}");
        }
        else
        {
            transform.ProxyRequest.Headers.Authorization = AuthenticationHeaderValue.Parse(signer.BuildApiAuthorizationHeader(transform.ProxyRequest.Method, requestUri, session.LiveSessionToken ?? ""));
        }

        return ValueTask.CompletedTask;
    });
});

builder.Services.AddRazorPages();

var app = builder.Build();

app.UseForwardedHeaders();

app.UseCors("AllowedOrigins");
// Reject websocket upgrade attempts from disallowed origins.
// Built-in CORS middleware does not apply to the WebSocket upgrade handshake —
// check Origin on the upgrade request and block if not allowed.
// See: https://microsoft.github.io/reverse-proxy/articles/websocket.html
//      https://learn.microsoft.com/aspnet/core/fundamentals/websockets
app.Use(async (context, next) =>
{
    if (context.WebSockets.IsWebSocketRequest)
    {
        var origin = context.Request.Headers.Origin.ToString();
        if (string.IsNullOrEmpty(origin) || !allowedOrigins.Contains(origin, StringComparer.OrdinalIgnoreCase))
        {
            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.CompleteAsync();
            return;
        }
    }
    await next();
});

app.UseStaticFiles();
app.MapRazorPages();

app.MapHealthChecks("/health");
app.MapGet("/session", (Session s) => new
{
    state = s.State,
    time = s.LastPingTime,
    last = s.LastTickleResponse,
    live = !string.IsNullOrEmpty(s.LiveSessionToken)
});

app.MapReverseProxy();

app.Run();
