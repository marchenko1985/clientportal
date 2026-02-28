# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
dotnet build             # build
dotnet run --project Gateway # run — launchSettings.json sets http://localhost:5000 and ASPNETCORE_ENVIRONMENT=Development
```

`TreatWarningsAsErrors=True` is set in the project — warnings fail the build.

### Manual testing

See `Test.md` for curl and WebSocket smoke test commands. There are no automated tests.

---

## Architecture

Four source files in `Gateway/`, plus a `Pages/` sub-folder with the status UI:

| File / Folder        | Role                                                                                                                                                                          |
| -------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Program.cs`         | DI wiring, middleware pipeline, YARP transform                                                                                                                                |
| `Config.cs`          | Options class bound from the `Config` config section                                                                                                                          |
| `Signer.cs`          | Stateless OAuth signing — live session token request and regular API requests                                                                                                 |
| `Session.cs`         | `BackgroundService` that owns the IBKR session lifecycle; also contains `HealthCheck` and the JSON response record types (`TickleResponse`, `Server`, `AuthenticationStatus`) |
| `Pages/Index.cshtml` | Razor Pages status page served at `/` — shows session state indicators                                                                                                        |

### Session lifecycle

`Session` runs as a `BackgroundService` and is also registered as a `singleton` so YARP transforms can read `LiveSessionToken` and `LastTickleResponse` directly. On startup it:

1. Calls `POST /v1/api/oauth/live_session_token` (RSA-SHA256 signed) and completes the DH exchange to derive `LiveSessionToken`.
2. Calls `POST /v1/api/iserver/auth/ssodh/init` (HMAC-SHA256 signed) to establish the brokerage session.
3. Enters a keep-alive loop that calls `POST /v1/api/tickle` every `PingInterval`.

On any failure, it waits `ReinitializeDelay` and restarts from step 1.

### YARP transform

All proxied routes share a single request transform registered in `Program.cs`. WebSocket and HTTP requests are handled differently:

- **WebSocket** (`/v1/api/ws`): strips `Authorization`, replaces `Cookie` with the tickle session token, appends `oauth_token` as a query parameter.
- **HTTP**: builds and sets a full `Authorization: OAuth …` header via `Signer.BuildApiAuthorizationHeader`.

The detection uses `Headers.Upgrade == "websocket"` rather than `HttpContext.WebSockets.IsWebSocketRequest` (the latter does not work at the transform stage).

### Config and options

`Config` is bound from the `Config` JSON section. The three `byte[]` fields (`AccessTokenSecret`, `DhPrimeBytes`, `PrivateSignatureBytes`) are stored as base64 in `appsettings.json` — the .NET binder decodes them automatically. A `PostConfigure` in `Program.cs` converts them to their runtime forms (`BigInteger` and `RSA`); properties needed only at runtime (`DhPrime`, `PrivateSignature`) have `internal set` and are not config-bound.

See `Gateway/Config.cs` (the `DhPrimeBytes`, `AccessTokenSecret`, `PrivateSignatureBytes` XML comments) for the one-time extraction commands used to produce the base64 values from the PEM files that IBKR provides.

### HTTP client logging — named options gotcha

`AddExtendedHttpClientLogging` registers `LoggingOptions` under the **named** key matching the HTTP client name (`"Session"`). A global `services.Configure<LoggingOptions>(o => …)` targets the unnamed default instance and is **silently ignored**. Always configure logging options via the `Action<LoggingOptions>` overload on the builder:

```csharp
.AddExtendedHttpClientLogging(o =>
{
    builder.Configuration.GetSection("HttpClientLogging").Bind(o);  // scalar props from config
    o.RequestBodyContentTypes.Add("application/json");              // ISet — can't bind from JSON
    // …
})
```

**Double slash in logged request paths** — log lines from `AddExtendedHttpClientLogging` look like:

```
POST api.ibkr.com//v1/api/oauth/live_session_token
```

This is a formatting artefact in the library: it assembles the log message as `{Host}/{Path}` where `{Path}` already carries a leading `/`, producing a double slash. The underlying `HttpRequestMessage.RequestUri` is correct (`https://api.ibkr.com/v1/api/oauth/live_session_token`) and the wire request is fine. There is no bug to fix — the library's internal formatter cannot be overridden.

`AddRedaction()` alone does not guarantee plain-text header logging — explicitly register `NullRedactor` for the relevant classification:

```csharp
services.AddRedaction(rb => rb.SetRedactor<NullRedactor>(
    DataClassificationSet.FromDataClassification(DataClassification.Unknown)));
```

### Middleware order

```
UseForwardedHeaders → UseCors → WebSocket origin check (inline middleware) → MapHealthChecks / MapGet / MapReverseProxy
```

`UseForwardedHeaders` must come first — CORS and routing decisions depend on the correct scheme and host being resolved from `X-Forwarded-*` headers set by nginx. The WebSocket origin middleware runs after CORS because `UseCors` does not enforce CORS on WebSocket upgrade requests.

---

## Reference docs

- `Gateway/README.md` — Gateway project overview, proxied routes, running instructions
- `Test.md` — curl and WebSocket smoke test commands
- Implementation details (session lifecycle, OAuth signing, config fields) live as XML doc comments in `Gateway/Session.cs`, `Gateway/Signer.cs`, `Gateway/Config.cs`
