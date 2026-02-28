![Interactive Brokers](https://ndcdyn.interactivebrokers.com/images/common/logos/ibkr/interactive-brokers.svg)

# IBKR OAuth Gateway

A minimal .NET 10 reverse proxy that authenticates [IBKR Web API](https://www.interactivebrokers.com/campus/ibkr-api-page/webapi-doc/) requests using the IBKR two-layer OAuth 1.0 protocol (RSA-SHA256 + Diffie-Hellman live session token exchange).

It maintains a persistent brokerage session in the background and transparently signs all proxied HTTP and WebSocket connections — your front-end app talks to it like a plain API, with no OAuth logic on the client side.

# IBKR Web Api

- [Reference](https://www.interactivebrokers.com/campus/ibkr-api-page/webapi-ref/)
- [Changelog](https://www.interactivebrokers.com/campus/ibkr-api-page/web-api-changelog/)
- [WebSockets](https://www.interactivebrokers.com/campus/ibkr-api-page/cpapi-v1/#websockets)

---

## How it works

1. **Session startup** — calls `POST /v1/api/oauth/live_session_token` (RSA-SHA256 signed, Diffie-Hellman key exchange) to derive a live session token, then calls `POST /v1/api/iserver/auth/ssodh/init` to activate the brokerage session.
2. **Keep-alive** — pings `POST /v1/api/tickle` every minute to prevent session expiry.
3. **Request signing** — every proxied HTTP request gets an `Authorization: OAuth …` header built with HMAC-SHA256 (live session token as key). WebSocket upgrades use a session cookie and `oauth_token` query parameter instead.
4. **Auto-reconnect** — on any network or session failure the full OAuth handshake restarts automatically after a brief delay.

---

## Prerequisites

- [.NET 10 SDK](https://dotnet.microsoft.com/download)
- An IBKR OAuth application registration — see [Config.md § Retrieving Keys](Config.md#retrieving-keys) for setup instructions and the one-time credential extraction commands

---

## Configuration

All values live under the `Config` JSON key in `appsettings.json`. See `Config.cs` for the full reference:

- OAuth credential fields (`ConsumerKey`, `AccessToken`, `AccessTokenSecret`, `DhPrimeBytes`, `PrivateSignatureBytes`) and how to extract them from the PEM files IBKR provides
- Timing options (`PingInterval`, `ReinitializeDelay`)
- HTTP resilience pipeline (`HttpStandardResilienceOptions`)
- CORS (`AllowedOrigins`), forwarded headers, logging

Secrets are kept out of source control using environment-specific config files:

| File                           | Purpose                                                      |
| ------------------------------ | ------------------------------------------------------------ |
| `appsettings.json`             | Committed — non-secret defaults (timing, resilience, routes) |
| `appsettings.Development.json` | Gitignored — local credentials                               |
| `appsettings.Production.json`  | Gitignored — production credentials                          |

In production, credentials can also be injected as environment variables (e.g. `Config__ConsumerKey`).

---

## Running

### Local development

```bash
dotnet run --project Gateway
```

`Gateway/Properties/launchSettings.json` binds to `http://localhost:5001` and sets `ASPNETCORE_ENVIRONMENT=Development`, which loads credentials from `Gateway/appsettings.Development.json`.

See [Test.md](../Test.md) for curl and WebSocket smoke test commands.

### Production (systemd + nginx)

The app listens on plain HTTP (`http://127.0.0.1:5000`); nginx handles TLS termination and forwards `X-Forwarded-*` headers. See [Deployment.md](../Deployment.md) for:

- Complete nginx site config with WebSocket proxying and TLS via Let's Encrypt
- systemd service unit (`ibkr-gateway.service`)
- Rationale for middleware ordering and header handling

---

## Proxied routes

The following IBKR API routes are proxied and signed automatically. Add more under `ReverseProxy:Routes` in `appsettings.json`.

| Route                                | Method                    | Description                          |
| ------------------------------------ | ------------------------- | ------------------------------------ |
| `/v1/api/ws`                         | `GET` (WebSocket upgrade) | IBKR streaming market data WebSocket |
| `/v1/api/tickle`                     | `POST`                    | Session keep-alive                   |
| `/v1/api/iserver/secdef/search`      | `GET`                     | Security definition search           |
| `/v1/api/iserver/marketdata/history` | `GET`                     | Market data history                  |

Internal endpoints (not proxied to IBKR):

| Route      | Description                                                 |
| ---------- | ----------------------------------------------------------- |
| `/`        | Session status page — shows live session state in a browser |
| `/health`  | ASP.NET health check                                        |
| `/session` | JSON session state (restricted to localhost by nginx)       |

---

## Reference docs

Key implementation details live as XML doc comments directly on the source files:
`Config.cs`, `Session.cs`, `Signer.cs`.

See [`../Test.md`](../Test.md) for curl and WebSocket smoke test commands.
