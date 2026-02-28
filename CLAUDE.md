# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
dotnet build             # build
dotnet run --project Gateway       # run — launchSettings.json sets http://localhost:5001 and ASPNETCORE_ENVIRONMENT=Development
dotnet run --project CookieGateway # run — launchSettings.json sets http://localhost:5001 and ASPNETCORE_ENVIRONMENT=Development
dotnet run --project Feed          # run — launchSettings.json sets http://localhost:5002 and ASPNETCORE_ENVIRONMENT=Development
```

`TreatWarningsAsErrors=True` is set in projects — warnings fail the build.

## Agreements

We have decided to store docs as xml doc strings close to source code, if code edited make sure to update its docs as well to keep them up to date.

### Manual testing

See `Test.md` for curl and WebSocket smoke test commands. There are no automated tests.

---

## Architecture

### Gateway project

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

### Production environmnet gotcha

Attempts to run:

```bash
ASPNETCORE_ENVIRONMENT=Production dotnet run --project Gateway
```

will not run in app in production environment, launchSettings.json takes preference and overrides it back to production, if needed for temporary testing - just edit launchSettings.json instead

### Middleware order

```
UseForwardedHeaders → UseCors → WebSocket origin check (inline middleware) → MapHealthChecks / MapGet / MapReverseProxy
```

`UseForwardedHeaders` must come first — CORS and routing decisions depend on the correct scheme and host being resolved from `X-Forwarded-*` headers set by nginx. The WebSocket origin middleware runs after CORS because `UseCors` does not enforce CORS on WebSocket upgrade requests.

---

## CookieGateway project

Alternative gateway that authenticates with IBKR using username/password (SRP-6) instead of OAuth signing. Drop-in replacement for `Gateway` — runs on the same port 5001.

### Key files

| File / Folder | Role |
|---|---|
| `Program.cs` | DI wiring, middleware pipeline, YARP transform |
| `Config.cs` | Options bound from the `Config` config section (Username, Password, UserAgent, PingInterval, ReinitializeDelay) |
| `Session.cs` | `BackgroundService` — SRP login, cookie storage, keep-alive; exposes `SessionCookie` for the YARP transform |
| `Login/` | SRP-6 (`SprClient`), RSA-e3 (`RsaUtils`), SSODH DH (`SsoDh`) — ports of IBKR's JS crypto |
| `Extensions/` | `PostAsFormAsync`, `ToUnsignedBigInteger`, `ToUnsignedHexString` helpers |
| `Pages/Index.cshtml` | Status page at `/` |

### Session lifecycle

`Session` runs as a `BackgroundService`. On startup it:

1. Performs a full SRP-6 login on `ndcdyn.interactivebrokers.com` (7 steps: INIT → COMPLETEAUTH → Dispatcher).
2. Calls `POST /v1/api/iserver/auth/ssodh/init` to activate the brokerage session.
3. Enters a keep-alive loop calling `POST /v1/api/tickle` every `PingInterval`.

Cookies are stored in-memory as `SessionCookie` (a `name=value; ...` string). `Set-Cookie` headers from all API responses are merged into this string.

### YARP transform

The single request transform injects `Cookie: <SessionCookie>` on all proxied requests (both HTTP and WebSocket). No OAuth Authorization header is built or sent.

### Credentials

Set `Username` and `Password` in `CookieGateway/appsettings.Development.json` (gitignored) or via env vars `Config__Username` / `Config__Password`.

---

## Feed project

WebSocket multiplexer that fans IBKR market data from one upstream connection to many browser clients.

### Key services

| File | Role |
|---|---|
| `Feed/Connection.cs` | `BackgroundService` — owns the single upstream IBKR WebSocket; reconnects with exponential back-off; publishes `connected`/`authenticated` events on `SystemMessages` channel |
| `Feed/Snapshots.cs` | Thread-safe `(conid, field) → value` cache; deduplicates writes; publishes change events; supports `ClearAll()` after prolonged disconnect |
| `Feed/Subscriptions.cs` | Per-client field tracking; shrinkable field union; `Action<int, string[]?>` callback fires after `UnsubscribeDelay` |
| `Feed/Hub.cs` | `BackgroundService` — accepts browser WebSocket clients; batches ticks; broadcasts system events |
| `Feed/Program.cs` | DI wiring; `/ws`, `/health`, `/status`, `/` endpoints; `FeedHealthCheck` |

### Subscription protocol

**Client → server** (raw text frames):
- `smd+{conid}+{"fields":["31","84"]}` — subscribe
- `umd+{conid}+{}` — unsubscribe

**Server → client** (JSON envelope):
- `{"topic":"connected","data":true/false}` — upstream connection change
- `{"topic":"authenticated","data":true/false}` — upstream auth change
- `{"topic":"batch","data":[{conid,field:val,…}]}` — market-data ticks

### Reconnect / stale-cache behaviour

After 3 consecutive upstream failures `Connection` calls `Snapshots.ClearAll()` to prevent new browser clients from seeing data that may be hours old.

### Field-union shrink

Each client's requested fields are tracked individually in `Subscriptions`. When a client disconnects the union is recomputed; if it shrank, `onDelayedChange(conid, newFields)` fires after `UnsubscribeDelay`. `null` newFields means full unsubscribe; non-null means `Connection.Subscribe` sends `umd`+`smd` with the smaller field list.

---

## Reference docs

- `Gateway/README.md` — Gateway project overview, proxied routes, running instructions
- `CookieGateway/README.md` — CookieGateway project overview, credentials setup, smoke tests
- `Feed/README.md` — Feed project overview, architecture, wire protocol, endpoints
- `Test.md` — curl and WebSocket smoke test commands
- Implementation details (session lifecycle, OAuth signing, config fields) live as XML doc comments in `Gateway/Session.cs`, `Gateway/Signer.cs`, `Gateway/Config.cs`
