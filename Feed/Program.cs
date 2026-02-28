using Microsoft.Extensions.Diagnostics.HealthChecks;
using Microsoft.Extensions.Options;
using Feed;

var builder = WebApplication.CreateBuilder(args);

var allowedOrigins = builder.Configuration.GetSection("AllowedOrigins").Get<string[]>() ?? [];

if (allowedOrigins.Length > 0) builder.Services.AddCors(options => options.AddPolicy("AllowedOrigins", policy => policy.WithOrigins(allowedOrigins).AllowAnyHeader().AllowAnyMethod()));

builder.Services.AddOptions<Config>().Bind(builder.Configuration.GetSection(nameof(Config))).ValidateOnStart();

builder.Services.AddSingleton<Snapshots>();
builder.Services.AddSingleton<Connection>().AddHostedService(p => p.GetRequiredService<Connection>());
builder.Services.AddSingleton<Subscriptions>(p =>
{
    var conn = p.GetRequiredService<Connection>();
    var snap = p.GetRequiredService<Snapshots>();
    return new Subscriptions((conid, newFields) =>
    {
        if (newFields == null)
        {
            conn.Unsubscribe(conid);
            snap.RemoveConid(conid);
        }
        else
        {
            conn.Subscribe(conid, newFields);
        }
    }, p.GetRequiredService<IOptions<Config>>(), p.GetRequiredService<ILogger<Subscriptions>>());
});
builder.Services.AddSingleton<Hub>().AddHostedService(p => p.GetRequiredService<Hub>());

builder.Services.AddHealthChecks().AddCheck<FeedHealthCheck>("upstream");

var app = builder.Build();

if (allowedOrigins.Length > 0) app.UseCors("AllowedOrigins");
app.UseWebSockets();
app.UseStaticFiles();

app.MapGet("/status", (Connection conn, Subscriptions subs, Snapshots snap, Hub hub) => Results.Json(new
{
    connection = new
    {
        state = conn.State,
        reconnectAttempts = conn.ReconnectAttempts,
    },
    subscriptions = new
    {
        activeConids = subs.State.Count(s => s.clients > 0),
        pendingChanges = subs.State.Count(s => s.pendingChange),
        details = subs.State,
    },
    snapshots = new { entries = snap.Count },
    hub = new
    {
        connectedClients = hub.ConnectedClients,
        activeSubscriptions = hub.ActiveSubscriptions,
    }
}));

app.MapHealthChecks("/health");

app.Map("/ws", async (HttpContext ctx, Hub hub, IHostApplicationLifetime lifetime) =>
{
    if (!ctx.WebSockets.IsWebSocketRequest) { ctx.Response.StatusCode = 426; return; }
    if (allowedOrigins.Length > 0 && !allowedOrigins.Contains(ctx.Request.Headers.Origin.ToString())) { ctx.Response.StatusCode = 403; return; }
    var ws = await ctx.WebSockets.AcceptWebSocketAsync(new WebSocketAcceptContext { DangerousEnableCompression = true });
    await hub.AddClientAsync(ws, ctx.RequestAborted, lifetime.ApplicationStopping);
});

app.Run();

/// <summary>
/// Health check that reports the upstream IBKR connection state.
/// Returns Healthy when authenticated, Degraded when connected but not yet authenticated,
/// and Unhealthy otherwise.
/// </summary>
internal sealed class FeedHealthCheck(Connection connection) : IHealthCheck
{
    public Task<HealthCheckResult> CheckHealthAsync(HealthCheckContext ctx, CancellationToken ct = default)
    {
        var result = connection.State switch
        {
            "authenticated" => HealthCheckResult.Healthy("Upstream authenticated"),
            "connected" => HealthCheckResult.Degraded("Connected but not yet authenticated"),
            _ => HealthCheckResult.Unhealthy($"Upstream {connection.State}"),
        };
        return Task.FromResult(result);
    }
}
