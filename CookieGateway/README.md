# CookieGateway

Reverse proxy for the IBKR Web API that authenticates using username/password (SRP-6) and forwards all requests with browser-style session cookies — no OAuth signing required.

See the [root README](../README.md) for proxied API endpoints and smoke test commands.

## Why this exists

The OAuth-based `Gateway` is unreliable in practice: tickle responses consistently return `authenticated=false`. Cookie-based authentication (as used by the IBKR Client Portal web UI) is proven to work. `CookieGateway` keeps all of `Gateway`'s YARP proxy infrastructure and replaces the OAuth signing layer with a full SRP login flow.

## How it works

1. **SRP-6 login** on `ndcdyn.interactivebrokers.com`:
   - `GET /sso/Login` → JSESSIONID
   - `POST /sso/Authenticator (INIT)` → B, salt, RSA public key
   - Computes M1 (client proof), encrypts session key
   - `POST /sso/Authenticator (COMPLETEAUTH)` → verifies M2 (server proof)
   - Sets XYZAB cookies, `POST /sso/Dispatcher` → follows redirects, accumulates all cookies
2. Calls `POST /v1/api/iserver/auth/ssodh/init` to activate the brokerage session.
3. Enters a keep-alive loop calling `POST /v1/api/tickle` every `PingInterval`.

Cookies are stored in-memory in `Session.SessionCookie`. `Set-Cookie` headers from every API response are merged in so they stay current. On any failure, the service waits `ReinitializeDelay` and restarts from step 1.

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

## Running

```bash
dotnet run --project CookieGateway   # http://localhost:5001
```

Internal endpoints: `/` (status page), `/health`, `/session` (JSON, localhost only).

## Key files

| File                 | Role                                                                           |
| -------------------- | ------------------------------------------------------------------------------ |
| `Program.cs`         | DI wiring, middleware pipeline, YARP transform                                 |
| `Config.cs`          | Options bound from `Config` section                                            |
| `Session.cs`         | `BackgroundService` — SRP login, session lifecycle, cookie storage, keep-alive |
| `Login/SprClient.cs` | SRP-6 client (port of IBKR's srp.js)                                           |
| `Login/RsaUtils.cs`  | RSA-e3 encryption used during COMPLETEAUTH                                     |
| `Extensions/`        | `PostAsFormAsync`, `ToUnsignedBigInteger`, `ToUnsignedHexString` helpers       |
| `Pages/Index.cshtml` | Status page at `/`                                                             |
