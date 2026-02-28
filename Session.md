# Session — Why It Exists and How It Works

## The Problem

The IBKR API is not a simple REST API you can call on demand. Before any request can be
made, you must hold a valid **live session token**, and that token must be kept alive with
periodic pings. If pings stop, the session expires. If the session expires, you must go
through the full OAuth handshake again.

`Session` is a .NET `BackgroundService` that runs for the lifetime of the application and
owns this lifecycle entirely. The rest of the app (the reverse proxy transforms in
`Program.cs`) just reads `session.LiveSessionToken` — it never has to think about
authentication state.

---

## Lifecycle

```
  App start
      │
      ▼
  ┌─────────────────────────────────────────────────────┐
  │ InitializeAsync                                     │
  │  1. POST /v1/api/oauth/live_session_token  (OAuth)  │
  │  2. POST /v1/api/iserver/auth/ssodh/init            │
  │  3. First tickle (PingAsync)                        │
  └──────────────────────────┬──────────────────────────┘
                             │ success
                             ▼
                     State = "Ready"
                             │
                             ▼
  ┌──────────────────────────────────────────────────┐
  │ KeepAliveAsync (infinite loop)                   │
  │  every PingInterval: POST /v1/api/tickle         │
  └──────────────────────────────────────────────────┘
                             │ exception
                             ▼
                  State = "Reinitializing"
                  wait ReinitializeDelay
                  restart from InitializeAsync
```

On any error (network failure, expired session, IBKR restarting) the loop catches the
exception, logs it, waits `ReinitializeDelay` (5 s by default), and restarts from the
beginning. `OperationCanceledException` on the cancellation token exits cleanly.

---

## Step-by-Step: `InitializeAsync`

### Step 1 — Live session token handshake

```
POST /v1/api/oauth/live_session_token
Authorization: OAuth realm="limited_poa", diffie_hellman_challenge="...", ...
```

Delegates entirely to `Signer.BuildLiveSessionTokenAuthorizationHeader`. The signer returns
both the Authorization header string and the DH private exponent `b` (a `BigInteger`).
See `Signer.md` for the full cryptographic details.

The server responds with `diffie_hellman_response` (a hex-encoded BigInteger). Session
parses it and hands both values to `Signer.ComputeLiveSessionToken`, which produces the
live session token. The token is stored in `LiveSessionToken`.

```csharp
var dhResponseHex = json?["diffie_hellman_response"]?.ToString() ?? throw ...;
// Normalize to even length — Convert.FromHexString requires it,
// and DH values can have a leading nibble stripped.
var dhResponse = new BigInteger(
    Convert.FromHexString(dhResponseHex.Length % 2 == 0 ? dhResponseHex : "0" + dhResponseHex),
    isUnsigned: true, isBigEndian: true);
LiveSessionToken = signer.ComputeLiveSessionToken(dhResponse, dhRandom);
```

### Step 2 — SSO session initialization

```
POST /v1/api/iserver/auth/ssodh/init  { "publish": true, "compete": true }
```

This is an IBKR-specific step that activates the brokerage session after the OAuth handshake.
`publish: true` makes this the active session; `compete: true` allows taking over from
another active session on the same account.

### Step 3 — First tickle

Immediately calls `PingAsync` to confirm the session is alive and to populate
`LastTickleResponse` before the app reports `State = "Ready"`.

---

## Keep-Alive: `PingAsync`

```
POST /v1/api/tickle
```

Called every `PingInterval` (1 minute by default). The response is a `TickleResponse`
JSON object that contains:

| Field                              | Meaning                                                               |
| ---------------------------------- | --------------------------------------------------------------------- |
| `session`                          | WebSocket cookie value — used by the reverse proxy for WS connections |
| `ssoExpires`                       | Milliseconds until the SSO session expires                            |
| `iserver.authStatus.authenticated` | Whether the brokerage session is authenticated                        |
| `iserver.authStatus.connected`     | Whether connected to the IBKR gateway                                 |
| `iserver.authStatus.established`   | Whether the session is fully established and ready                    |
| `iserver.authStatus.competing`     | Whether another session is competing for the same account             |

The full response is stored in `LastTickleResponse`. The reverse proxy reads
`LastTickleResponse.Session` for the WebSocket cookie (`Cookie: api=<value>`).

After storing the response, `PingAsync` checks `iserver.authStatus.authenticated`. IBKR
can return HTTP 200 with `authenticated: false` when the brokerage session has silently
expired — in that case an `InvalidOperationException` is thrown so the outer loop
treats it the same as any other failure: `State = "Reinitializing"`, wait
`ReinitializeDelay`, restart from `InitializeAsync`.

All tickle requests (and SSO init) go through `CreateSignedRequest`, which uses
`Signer.BuildApiAuthorizationHeader` with the current `LiveSessionToken`.

---

## Public State (read by `Program.cs`)

| Property             | Type              | Used for                                                                                    |
| -------------------- | ----------------- | ------------------------------------------------------------------------------------------- |
| `State`              | `string`          | `/session` endpoint — reports `"Initializing"`, `"Ready"`, `"Reinitializing"`, `"Stopping"` |
| `LiveSessionToken`   | `string?`         | Signing every proxied API request (HMAC-SHA256 key)                                         |
| `LastTickleResponse` | `TickleResponse?` | WebSocket `Cookie: api=<session>` header; also exposed on `/session`                        |
| `LastPingTime`       | `DateTime?`       | Exposed on `/session` for health checking                                                   |

---

## WebSocket vs. HTTP Requests (in `Program.cs`)

The reverse proxy transform handles both request types differently:

**HTTP requests** — signed with the live session token:

```csharp
signer.BuildApiAuthorizationHeader(method, uri, session.LiveSessionToken ?? "")
```

**WebSocket upgrades** — IBKR's WebSocket endpoint does not use OAuth headers. Instead:

- The `Authorization` header is stripped.
- A `Cookie: api=<session>` header is added (the session token from the last tickle).
- The `oauth_token` is appended as a query parameter.

The WebSocket detection uses the `Upgrade` header rather than
`HttpContext.WebSockets.IsWebSocketRequest` because the latter returns `false` at the
transform stage (the upgrade has not been accepted yet at that point).

---

## Configuration (`Config` section in `appsettings.json`)

| Key                 | Default    | Meaning                                                      |
| ------------------- | ---------- | ------------------------------------------------------------ |
| `PingInterval`      | `00:01:00` | How often to tickle. Keep well under IBKR's session timeout. |
| `ReinitializeDelay` | `00:00:05` | How long to wait before retrying after a failure.            |

`HttpResilience` under `Config` configures retry, timeout, and circuit-breaker policies
for the `HttpClient` used by `Session` (backed by `Microsoft.Extensions.Http.Resilience`).
