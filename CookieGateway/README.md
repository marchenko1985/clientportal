# CookieGateway

Reverse proxy for the IBKR Web API that authenticates using username/password (SRP-6) and forwards all requests with browser-style session cookies — no OAuth signing required.

## Why this exists

The OAuth-based `Gateway` project is unreliable in practice: tickle responses consistently return `authenticated=false`. Cookie-based authentication (as used by the IBKR Client Portal web UI) is proven to work. `CookieGateway` keeps all of `Gateway`'s YARP proxy infrastructure and replaces the OAuth signing layer with a full SRP login flow.

## Architecture

| File | Role |
|------|------|
| `Program.cs` | DI wiring, middleware pipeline, YARP transform |
| `Config.cs` | Options bound from the `Config` config section |
| `Session.cs` | `BackgroundService` — SRP login, session lifecycle, cookie storage, keep-alive |
| `Login/SprClient.cs` | SRP-6 client (port of IBKR's srp.js) |
| `Login/RsaUtils.cs` | RSA-e3 encryption used during COMPLETEAUTH |
| `Login/SsoDh.cs` | SSODH Diffie-Hellman (unused directly; available if needed) |
| `Extensions/` | `PostAsFormAsync`, `ToUnsignedBigInteger`, `ToUnsignedHexString` helpers |
| `Pages/Index.cshtml` | Status page at `/` |

### Session lifecycle

`Session` runs as a `BackgroundService`. On startup it:

1. Performs a full SRP-6 login on `ndcdyn.interactivebrokers.com`:
   - `GET /sso/Login` → JSESSIONID
   - `POST /sso/Authenticator (INIT)` → B, salt, RSA public key
   - Computes M1 (client proof), encrypts session key
   - `POST /sso/Authenticator (COMPLETEAUTH)` → verifies M2 (server proof)
   - Sets XYZAB cookies, `POST /sso/Dispatcher` → follows redirects, accumulates all cookies
2. Calls `POST /v1/api/iserver/auth/ssodh/init` to activate the brokerage session.
3. Enters a keep-alive loop calling `POST /v1/api/tickle` every `PingInterval`.

Cookies are stored in-memory in `Session.SessionCookie`. `Set-Cookie` headers from every API response are merged into this string so it stays current.

On any failure, the service waits `ReinitializeDelay` and restarts from step 1.

### YARP transform

All proxied routes share a single request transform that:
- Removes any `Authorization` and `Cookie` headers from the incoming request
- Injects `Cookie: <SessionCookie>` on both HTTP and WebSocket requests
- Adds the configured `User-Agent` header

## Running

```bash
dotnet run --project CookieGateway   # http://localhost:5001
```

Status page: `http://localhost:5001/`
Health check: `http://localhost:5001/health`
Session JSON: `http://localhost:5001/session`

## Configuration

Credentials are **not** committed to source control. Add them to `CookieGateway/appsettings.Development.json` (gitignored):

```json
{
  "Config": {
    "Username": "your_ibkr_username",
    "Password": "your_ibkr_password"
  }
}
```

Or via environment variables:

```bash
Config__Username=your_ibkr_username Config__Password=your_ibkr_password dotnet run --project CookieGateway
```

## Proxied routes

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/v1/api/ws` | WebSocket market data stream |
| `POST` | `/v1/api/tickle` | Keep-alive (also used by external callers) |
| `GET` | `/v1/api/iserver/secdef/search` | Security definition search |
| `GET` | `/v1/api/iserver/marketdata/history` | Market data history |

All routes proxy to `https://api.ibkr.com`.

## Smoke tests

```bash
# Security definition search
curl "http://localhost:5001/v1/api/iserver/secdef/search?symbol=AAPL"

# Health check
curl http://localhost:5001/health

# Session state
curl http://localhost:5001/session
```
