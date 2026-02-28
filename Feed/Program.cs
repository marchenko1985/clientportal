using Microsoft.Extensions.Options;
using Feed;

var builder = WebApplication.CreateBuilder(args);

var allowedOrigins = builder.Configuration.GetSection("AllowedOrigins").Get<string[]>() ?? [];

if (allowedOrigins.Length > 0) builder.Services.AddCors(options => options.AddPolicy("AllowedOrigins", policy => policy.WithOrigins(allowedOrigins).AllowAnyHeader().AllowAnyMethod()));

builder.Services.AddOptions<Config>().Bind(builder.Configuration.GetSection(nameof(Config))).ValidateOnStart();

builder.Services.AddSingleton<Connection>().AddHostedService(p => p.GetRequiredService<Connection>());
builder.Services.AddSingleton<Subscriptions>(p =>
{
    var socketService = p.GetRequiredService<Connection>();
    var snapshotStore = p.GetRequiredService<Snapshots>();
    return new Subscriptions(conid =>
    {
        socketService.Unsubscribe(conid);
        snapshotStore.RemoveConid(conid);
    }, p.GetRequiredService<IOptions<Config>>(), p.GetRequiredService<ILogger<Subscriptions>>());
});
builder.Services.AddSingleton<Snapshots>();
builder.Services.AddSingleton<Hub>().AddHostedService(p => p.GetRequiredService<Hub>());


var app = builder.Build();

if (allowedOrigins.Length > 0) app.UseCors("AllowedOrigins");
app.UseWebSockets();

app.MapGet("/", () => "Hello World!");

app.Map("/ws", async (HttpContext ctx, Hub hub, IHostApplicationLifetime lifetime) =>
{
    if (!ctx.WebSockets.IsWebSocketRequest) { ctx.Response.StatusCode = 426; return; }
    if (!allowedOrigins.Contains(ctx.Request.Headers.Origin.ToString())) { ctx.Response.StatusCode = 403; return; }
    var ws = await ctx.WebSockets.AcceptWebSocketAsync(new WebSocketAcceptContext { DangerousEnableCompression = true });
    await hub.AddClientAsync(ws, ctx.RequestAborted, lifetime.ApplicationStopping);
});

app.Run();
