using Microsoft.Extensions.Compliance.Classification;
using Microsoft.Extensions.Compliance.Redaction;
using Microsoft.Extensions.Http.Resilience;
using Microsoft.Extensions.Options;
using CookieGateway;
using Yarp.ReverseProxy.Transforms;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.ConfigureKestrel(o => o.AddServerHeader = false); // do not tell we are written in dotnet

var allowedOrigins = builder.Configuration.GetSection("AllowedOrigins").Get<string[]>() ?? [];

builder.Services.AddOptions<Config>().Bind(builder.Configuration.GetSection(nameof(Config))).ValidateOnStart();

if (allowedOrigins.Length > 0) builder.Services.AddCors(options => options.AddPolicy("AllowedOrigins", policy => policy.WithOrigins(allowedOrigins).AllowAnyHeader().AllowAnyMethod().AllowCredentials()));
builder.Services.AddHealthChecks().AddCheck<HealthCheck>(nameof(HealthCheck));

builder.Services.AddRedaction(redactionBuilder => redactionBuilder.SetRedactor<NullRedactor>(DataClassificationSet.FromDataClassification(DataClassification.Unknown)));
builder.Services.AddHttpClient(nameof(Session), (provider, client) =>
{
    var config = provider.GetRequiredService<IOptions<Config>>().Value;
    client.BaseAddress = new Uri(builder.Configuration["ReverseProxy:Clusters:InteractiveBrokers:Destinations:Primary:Address"] ?? throw new InvalidOperationException("Missing InteractiveBrokers base address"));
    client.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", config.UserAgent);
}).ConfigurePrimaryHttpMessageHandler(() => new HttpClientHandler { UseCookies = false }) // cookies managed manually in Session.cs
  .AddExtendedHttpClientLogging(o =>
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
    var session = ctx.Services.GetRequiredService<Session>();
    var config = ctx.Services.GetRequiredService<IOptions<Config>>().Value;

    ctx.AddRequestTransform(transform =>
    {
        // var isWebSocket = transform.HttpContext.WebSockets.IsWebSocketRequest; // this one does not work
        var isWebSocket = transform.HttpContext.Request.Headers.Upgrade.ToString().Equals("websocket", StringComparison.OrdinalIgnoreCase);

        transform.ProxyRequest.Headers.TryAddWithoutValidation("User-Agent", config.UserAgent);
        transform.ProxyRequest.Headers.Remove("Authorization");
        transform.ProxyRequest.Headers.Remove("Cookie");
        if (!string.IsNullOrEmpty(session.SessionCookie))
            transform.ProxyRequest.Headers.TryAddWithoutValidation("Cookie", session.SessionCookie);

        if (isWebSocket)
        {
            // RequestUri is left unchanged — no oauth_token query param needed for cookie-based auth.
            // if (!allowedOrigins.Contains(ctx.Request.Headers.Origin.ToString())) { ctx.Response.StatusCode = 403; return; }
        }

        return ValueTask.CompletedTask;
    });
});

builder.Services.AddRazorPages();

var app = builder.Build();

app.UseForwardedHeaders();

if (allowedOrigins.Length > 0)
{
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
}

app.UseStaticFiles();
app.MapRazorPages();

app.MapHealthChecks("/health");
app.MapGet("/session", (Session s) => new
{
    state = s.State,
    time = s.LastPingTime,
    last = s.LastTickleResponse,
    cookie = !string.IsNullOrEmpty(s.SessionCookie)
});

app.MapReverseProxy();

app.Run();
