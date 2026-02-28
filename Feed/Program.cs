using Microsoft.Extensions.Options;
using Feed;

var builder = WebApplication.CreateBuilder(args);

var allowedOrigins = builder.Configuration.GetSection("AllowedOrigins").Get<string[]>() ?? [];

if (allowedOrigins.Length > 0) builder.Services.AddCors(options => options.AddPolicy("AllowedOrigins", policy => policy.WithOrigins(allowedOrigins).AllowAnyHeader().AllowAnyMethod()));

builder.Services.AddOptions<Config>().Bind(builder.Configuration.GetSection(nameof(Config))).ValidateOnStart();

builder.Services.AddSingleton<SnapshotStore>();
builder.Services.AddSingleton<SocketService>().AddHostedService(p => p.GetRequiredService<SocketService>());
builder.Services.AddSingleton<SubscriptionsStore>(p =>
{
    var socketService = p.GetRequiredService<SocketService>();
    var snapshotStore = p.GetRequiredService<SnapshotStore>();
    return new SubscriptionsStore(conid =>
    {
        socketService.Unsubscribe(conid);
        snapshotStore.RemoveConid(conid);
    }, p.GetRequiredService<IOptions<Config>>(), p.GetRequiredService<ILogger<SubscriptionsStore>>());
});
builder.Services.AddSingleton<HubService>().AddHostedService(p => p.GetRequiredService<HubService>());


var app = builder.Build();

if (allowedOrigins.Length > 0) app.UseCors("AllowedOrigins");
app.UseWebSockets();

app.MapGet("/", () => "Hello World!");

app.Map("/ws", async (HttpContext ctx, HubService hub, IHostApplicationLifetime lifetime) =>
{
    if (!ctx.WebSockets.IsWebSocketRequest) { ctx.Response.StatusCode = 426; return; }
    if (!allowedOrigins.Contains(ctx.Request.Headers.Origin.ToString())) { ctx.Response.StatusCode = 403; return; }
    var ws = await ctx.WebSockets.AcceptWebSocketAsync(new WebSocketAcceptContext { DangerousEnableCompression = true });
    await hub.AddClientAsync(ws, ctx.RequestAborted, lifetime.ApplicationStopping);
});

app.Run();
