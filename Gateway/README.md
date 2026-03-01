![Interactive Brokers](https://ndcdyn.interactivebrokers.com/images/common/logos/ibkr/interactive-brokers.svg)

# IBKR OAuth Gateway

A minimal .NET 10 reverse proxy that authenticates [IBKR Web API](https://www.interactivebrokers.com/campus/ibkr-api-page/webapi-doc/) requests using IBKR two-layer OAuth 1.0 (RSA-SHA256 + Diffie-Hellman live session token exchange).

See the [root README](../README.md) for proxied API endpoints and smoke test commands.

## How it works

1. **Session startup** — calls `POST /v1/api/oauth/live_session_token` (RSA-SHA256 signed, DH key exchange) to derive a live session token, then calls `POST /v1/api/iserver/auth/ssodh/init` to activate the brokerage session.
2. **Keep-alive** — pings `POST /v1/api/tickle` every minute to prevent session expiry.
3. **Request signing** — every proxied HTTP request gets an `Authorization: OAuth …` header built with HMAC-SHA256 (live session token as key). WebSocket upgrades use a session cookie and `oauth_token` query parameter instead.
4. **Auto-reconnect** — on any failure the full OAuth handshake restarts automatically after a brief delay.

## Configuration

All values live under the `Config` JSON key. See `Config.cs` XML docs for the full reference, including how to extract the base64 credential values from the PEM files IBKR provides.

| File                           | Purpose                                                      |
| ------------------------------ | ------------------------------------------------------------ |
| `appsettings.json`             | Committed — non-secret defaults (timing, resilience, routes) |
| `appsettings.Development.json` | Gitignored — local credentials                               |
| `appsettings.Production.json`  | Gitignored — production credentials                          |

Credentials can also be injected as environment variables (e.g. `Config__ConsumerKey`).

## Running

```bash
dotnet run --project Gateway   # http://localhost:5001
```

Internal endpoints: `/` (status page), `/health`, `/session` (JSON, localhost only).

## Implementation notes

Key implementation details live as XML doc comments in `Config.cs`, `Session.cs`, and `Signer.cs`.
