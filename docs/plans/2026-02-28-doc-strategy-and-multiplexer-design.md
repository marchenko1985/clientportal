# Design: Documentation Strategy + WebSocket Multiplexer

Date: 2026-02-28

---

## Context

The ClientPortal repo is an IBKR OAuth gateway (YARP reverse proxy, .NET 10). A separate
demo at `ClientPortalSocket/Web` implements a WebSocket multiplexer that fans out IBKR
market data to multiple browser clients. The goal is to integrate the multiplexer into the
same solution and establish a consistent documentation strategy.

---

## Decision: Documentation Strategy

**Rule:** if it describes a class or method, it is an XML doc comment. If it describes the
whole project or requires a terminal, it is a root-level markdown file.

**Root-level markdown files (final state):**

| File | Contents |
|---|---|
| `README.md` | Repo-level overview pointing to `Web/` and `Multiplexer/` |
| `CLAUDE.md` | Architecture notes and gotchas for Claude Code |
| `Test.md` | curl / WebSocket test commands for both services |

Per-project `README.md` files live inside each project folder:

| File | Contents |
|---|---|
| `Web/README.md` | Web project overview, setup, routes (moved from root) |
| `Multiplexer/README.md` | Multiplexer overview, setup, wire protocol (new) |

**Deleted (content migrated to XML comments):**
- `Config.md` → XML comments on `Config.cs`
- `Session.md` → XML comments on `Session.cs`
- `Signer.md` → XML comments on `Signer.cs`
- `Systemd.md` → deleted by user
- `Deployment.md` → deleted by user

---

## Phase 1: Doc Cleanup (this task)

Scope: prep work before the Multiplexer project is added.

### 1. XML comments — `Session.cs`

Add a class-level `<summary>` / `<remarks>` covering:
- Role: BackgroundService that owns the IBKR session lifecycle for the lifetime of the app
- State machine: Initializing → Ready → (KeepAliveAsync loop) → Reinitializing on error
- Three-step init: POST live_session_token (RSA-SHA256 + DH) → POST ssodh/init → first tickle
- Keep-alive: POST tickle every PingInterval; throws if authenticated=false
- Reconnect: any exception → wait ReinitializeDelay → restart from InitializeAsync

Add property-level comments on `State`, `LiveSessionToken`, `LastTickleResponse`,
`LastPingTime`, `Healthy`.

Add method-level comments on `InitializeAsync` (step-by-step including the DH hex
normalization), `PingAsync` (authenticated-false guard), `CreateSignedRequest`.

### 2. XML comments — `Signer.cs`

Expand the existing class `<summary>` to cover:
- Two-layer OAuth: layer 1 = RSA-SHA256 + DH exchange (live session token), layer 2 =
  HMAC-SHA256 per-request signing using the live session token
- IBKR-specific base string prefix: `accessTokenSecretHex` prepended before the standard
  OAuth base string (live session token request only)

Add method-level comments on:
- `BuildLiveSessionTokenAuthorizationHeader` — DH challenge, parameter sort requirement
  (RFC 5849 §3.4.1.3.2), secret-hex prefix, RSA-PKCS1-SHA256 signature
- `BuildApiAuthorizationHeader` — standard HMAC-SHA256 OAuth, live session token as key
- `ComputeLiveSessionToken` — shared secret via modular exponentiation, signed big-endian
  serialization (Java BigInteger semantics required by IBKR), HMAC-SHA1 final step

### 3. XML comments — `Config.cs`

Add a class-level `<summary>` covering:
- Bound from the `Config` JSON section by the .NET options system
- byte[] fields are automatically base64-decoded by the .NET configuration binder
- DhPrime and PrivateSignature are computed by PostConfigure in Program.cs (not config-bound)
- IBKR key retrieval URL: https://ndcdyn.interactivebrokers.com/sso/Login?action=OAUTH&RL=1&ip2loc=US

Add property-level comments on all currently undocumented properties:
- `PingInterval` — how often /v1/api/tickle is called
- `ReinitializeDelay` — wait duration before retrying after session failure
- `OAuthRealm` — OAuth realm string, typically `limited_poa`
- `UserAgent` — User-Agent header value sent on all upstream requests
- `ConsumerKey` — assigned by IBKR at OAuth app registration
- `AccessToken` — OAuth access token assigned by IBKR
- `DhPrime` — computed from DhPrimeBytes by PostConfigure
- `PrivateSignature` — RSA key computed from PrivateSignatureBytes by PostConfigure

The existing `AccessTokenSecret`, `DhPrimeBytes`, and `PrivateSignatureBytes` XML comments
already contain the extraction shell commands — keep them as-is.

### 4. Move README.md → Web/README.md

- Move the file
- Update links: remove references to deleted docs (Config.md, Session.md, Signer.md,
  Nginx.md); update Test.md link to `../Test.md`
- Update `CLAUDE.md`: remove the reference docs table (Config.md, Signer.md, Session.md,
  Nginx.md), add a note that class/method docs live as XML comments in the source files;
  keep the Test.md reference as-is

### 5. Delete Config.md, Session.md, Signer.md

---

## Phase 2: Multiplexer Project (future task)

Add `Multiplexer/` project to the solution. The demo code (SocketService, HubService,
SubscriptionsStore, SnapshotStore, Program.cs) is brought in with minimal changes:

- `BaseAddress` config points to `ws://localhost:5000/v1/api/ws` (the YARP proxy) — no
  auth code needed in the multiplexer
- Project uses XML comments throughout (already done in demo)
- Clients connect to the multiplexer's `/ws` endpoint and send `smd+conid+{fields}` /
  `umd+conid+{}` messages; multiplexer handles upstream subscription deduplication,
  snapshots, and batched fan-out

A separate design doc will be written for Phase 2.
