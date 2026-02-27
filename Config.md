# Configuration Reference

## Retrieving Keys

You can retrieve keys by visiting

https://ndcdyn.interactivebrokers.com/sso/Login?action=OAUTH&RL=1&ip2loc=US

Notes:

- `action=OAUTH` in url is required, once logged in you will be landed to OAuth configuration page
- you might want to crate separate keys for you paper account rather than live one
- but only one account can be logged in at the same time
- this keys can be used with 2FA enabled accounts as well and will bypass 2FA

Find more [here](https://marchenko1985.github.io/ibkr-api-oauth/)

## Configuration

All values live under the `Config` key in `appsettings.json` and are bound to the `Config`
class by the .NET options system.

### Plain string fields

| Key           | Description                                       |
| ------------- | ------------------------------------------------- |
| `ConsumerKey` | Assigned by IBKR when registering the OAuth app   |
| `AccessToken` | OAuth access token assigned by IBKR               |
| `OAuthRealm`  | OAuth realm string (typically `limited_poa`)      |
| `UserAgent`   | `User-Agent` header sent on all upstream requests |

### Timing fields

| Key                 | Format     | Description                                              |
| ------------------- | ---------- | -------------------------------------------------------- |
| `PingInterval`      | `hh:mm:ss` | How often `/v1/api/tickle` keep-alive is sent            |
| `ReinitializeDelay` | `hh:mm:ss` | How long to wait before retrying after a session failure |

### Credential fields — base64-encoded byte arrays

The three fields below are stored as base64 strings. The .NET configuration binder
**automatically decodes** them into `byte[]` — no manual conversion in application code.

| Key                     | Description                                                    |
| ----------------------- | -------------------------------------------------------------- |
| `AccessTokenSecret`     | Decrypted secret bytes (see extraction below)                  |
| `DhPrimeBytes`          | Raw prime `p` from `dhparam.pem` (see extraction below)        |
| `PrivateSignatureBytes` | PKCS#8 DER bytes of the RSA signing key (see extraction below) |

After binding, `PostConfigure` in `Program.cs` converts the byte arrays into their runtime
forms — `DhPrimeBytes` → `BigInteger`, `PrivateSignatureBytes` → `RSA` key object.
See [Signer.md](Signer.md) for how these values are used in signing.

### One-time extraction from PEM files

IBKR provides three PEM files when you register an OAuth application. The commands below
were run once to produce the values now stored in `appsettings.json`. The PEM files are
not needed at runtime.

#### `DhPrimeBytes` — raw prime from `dhparam.pem`

`asn1parse` outputs the prime hex on the INTEGER line; `xxd -r -p` converts hex → binary;
`base64` encodes for JSON:

```bash
openssl asn1parse -in dhparam.pem | grep INTEGER | head -n 1 | cut -d: -f4 | xxd -r -p | base64
```

#### `AccessTokenSecret` — decrypt the IBKR-issued ciphertext

IBKR issues `AccessTokenSecret` as an RSA-PKCS1 ciphertext (base64-encoded). Decrypt it
with `private_encryption.pem`, then base64-encode the plaintext bytes for JSON:

```bash
echo "<ciphertext from IBKR>" \
  | base64 -d \
  | openssl pkeyutl -decrypt -pkeyopt rsa_padding_mode:pkcs1 -inkey private_encryption.pem \
  | base64
```

`private_encryption.pem` is the only file that can be safely discarded after this step.

#### `PrivateSignatureBytes` — strip PEM headers from `private_signature.pem`

PEM is base64-encoded DER with `-----BEGIN/END-----` headers. Stripping the headers gives
the raw PKCS#8 DER bytes, already base64-encoded:

```bash
grep -v "^-----" private_signature.pem | tr -d '\n'
```

The `-----BEGIN PRIVATE KEY-----` header confirms PKCS#8 format, which is what
`RSA.ImportPkcs8PrivateKey` expects at runtime.

### `HttpStandardResilienceOptions`

Configures the [standard resilience pipeline](https://learn.microsoft.com/dotnet/core/resilience/http-resilience)
applied to all outgoing IBKR API calls.

```json
"HttpStandardResilienceOptions": {
  "Retry": {
    "MaxRetryAttempts": 3,
    "Delay": "00:00:02",
    "UseJitter": true
  },
  "AttemptTimeout": { "Timeout": "00:00:15" },
  "TotalRequestTimeout": { "Timeout": "00:01:00" },
  "CircuitBreaker": {
    "BreakDuration": "00:00:30",
    "FailureRatio": 0.5,
    "MinimumThroughput": 4,
    "SamplingDuration": "00:00:30"
  }
}
```

---

## AllowedOrigins

List of origins permitted for CORS and WebSocket upgrade requests. Requests from origins
not in this list are rejected with `403`.

```json
"AllowedOrigins": ["https://example.com", "http://localhost:3000"]
```

In production, set this to the exact origin(s) of your front-end application.

---

## HTTP Client Logging

Controls structured logging of outgoing IBKR API requests and responses.
All fields live under the `HttpClientLogging` key.

| Key                                 | Type     | Description                                                             |
| ----------------------------------- | -------- | ----------------------------------------------------------------------- |
| `LogBody`                           | bool     | Include request and response bodies (for `application/json` content)    |
| `LogContentHeaders`                 | bool     | Include content-level headers (e.g. `Content-Type`, `Content-Length`)   |
| `LogRequestStart`                   | bool     | Emit an extra log entry when the request begins, before the response    |
| `RequestPathParameterRedactionMode` | string   | `None` to log URL paths as-is; `Loose` or `Strict` to redact parameters |
| `AllowedRequestHeaders`             | string[] | Request headers to include in logs (unlisted headers are never logged)  |
| `AllowedResponseHeaders`            | string[] | Response headers to include in logs                                     |

Request and response body content types (`application/json`) are hardcoded — only JSON
bodies are captured regardless of `LogBody`.

Header values are logged as plain text. In production, consider removing sensitive headers
from `AllowedRequestHeaders` (e.g. `Authorization`, `Cookie`) or replacing the `NullRedactor`
with a real redacting implementation.

---

## Logging

Standard [.NET logging configuration](https://learn.microsoft.com/dotnet/core/extensions/logging).

```json
"Logging": {
  "LogLevel": {
    "Default": "Information",
    "Microsoft.AspNetCore": "Warning"
  },
  "Console": {
    "FormatterName": "json"
  }
}
```

`Microsoft.Extensions.Http.Logging.HttpClientLogger` emits at `Information` level — the
`Default: Information` setting is sufficient to see all HTTP client log entries including
bodies and headers.

---

## Forwarded Headers

Configures the `ForwardedHeaders` middleware so that `X-Forwarded-For`, `X-Forwarded-Proto`,
and `X-Forwarded-Host` set by a reverse proxy (e.g. nginx) are trusted and applied.

```json
"ForwardedHeadersOptions": {
  "ForwardedHeaders": "XForwardedFor, XForwardedProto, XForwardedHost"
}
```

Only requests from loopback addresses (`127.0.0.1`, `::1`) are trusted by default.
No additional `KnownProxies` configuration is needed when the app runs behind nginx on
the same host.

---

## Reverse Proxy

Configures [YARP](https://microsoft.github.io/reverse-proxy/) routing from the gateway
to `https://api.ibkr.com`. Add routes here to expose additional IBKR API endpoints.

```json
"ReverseProxy": {
  "Routes": {
    "WebSocket": {
      "ClusterId": "InteractiveBrokers",
      "Match": { "Path": "/v1/api/ws", "Methods": ["GET"] }
    },
    "Ping": {
      "ClusterId": "InteractiveBrokers",
      "Match": { "Path": "/v1/api/tickle", "Methods": ["POST"] }
    },
    "Search": {
      "ClusterId": "InteractiveBrokers",
      "Match": { "Path": "/v1/api/iserver/secdef/search", "Methods": ["GET"] }
    },
    "History": {
      "ClusterId": "InteractiveBrokers",
      "Match": { "Path": "/v1/api/iserver/marketdata/history", "Methods": ["GET"] }
    }
  },
  "Clusters": {
    "InteractiveBrokers": {
      "Destinations": {
        "Primary": { "Address": "https://api.ibkr.com" }
      }
    }
  }
}
```

Each route is signed in `Program.cs` via a YARP request transform — WebSocket requests
use a session cookie and `oauth_token` query parameter; all other requests get a full
OAuth `Authorization` header built by `Signer`. See [Signer.md](Signer.md) for details.

---

## Runtime environment

The listening address and ASP.NET Core environment are controlled via environment variables,
not `appsettings.json`:

| Variable                 | Example                 | Description                      |
| ------------------------ | ----------------------- | -------------------------------- |
| `ASPNETCORE_URLS`        | `http://127.0.0.1:5000` | Kestrel bind address             |
| `ASPNETCORE_ENVIRONMENT` | `Production`            | Selects `appsettings.{env}.json` |

### appsettings layering

Configuration is merged in this order (later values override earlier ones):

1. `appsettings.json` — committed, no secrets
2. `appsettings.{Environment}.json` — gitignored, environment-specific overrides
3. Environment variables — for secrets in production (e.g. `Config__ConsumerKey`)

A typical `appsettings.Production.json` would override `AllowedOrigins`, `AllowedHosts`,
and the `Config` credential fields, leaving timing and resilience values from the base file.
