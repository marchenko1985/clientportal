# Feed

WebSocket multiplexer that fans IBKR market-data from a single upstream connection to multiple browser clients.

## Overview

Feed connects to the IBKR WebSocket endpoint (proxied through Gateway) as a single upstream client, maintains subscriptions for each requested contract (conid), and broadcasts tick updates to all interested browser clients over their own WebSocket connections.

- One upstream IBKR connection shared by all browser clients.
- Per-client field tracking — the upstream subscription shrinks when a client that requested extra fields disconnects.
- Typed `{topic, data}` protocol so browsers can distinguish system events from data batches.
- Snapshot cache on subscribe — new clients immediately receive the latest known value for every field.

## Architecture

```
Browser clients (WebSocket /ws)
        │  subscribe / unsubscribe / receive batches
        ▼
      Hub  ──────────────────────────────────────────────────┐
        │  Subscribe(conid, clientId, fields)                 │ reads SystemMessages
        ▼                                                     │ channel
  Subscriptions  ──► onDelayedChange callback                │
        │                       │                            │
        │ upstreamFields        ▼                            │
        │              Connection.Subscribe / Unsubscribe    │
        │                       │ upstream WebSocket         │
        │                       ▼                         Connection
        │                     IBKR  ──► Snapshots.Write       │
        │                                    │                │
        └────────────────────── read changes ┘                │
                                                              │
Hub reads SystemMessages ─────────────────────────────────────┘
broadcasts {topic,data} to all clients
```

## Configuration (`Config` section in `appsettings.json`)

| Key | Type | Description |
|---|---|---|
| `BaseAddress` | URI | IBKR WebSocket endpoint (e.g. `wss://localhost:5001/v1/api/ws`) |
| `PingInterval` | TimeSpan | How often to send a `tic` keepalive frame (e.g. `"00:00:30"`) |
| `BatchInterval` | TimeSpan | How often to flush accumulated ticks to browser clients (e.g. `"00:00:00.200"`) |
| `UnsubscribeDelay` | TimeSpan | Grace period before an upstream unsubscribe/field-change is sent (e.g. `"00:00:10"`) |

## Wire protocol

### Client → server

Raw text frames sent by the browser:

| Message | Meaning |
|---|---|
| `smd+{conid}+{"fields":["31","84"]}` | Subscribe to market data for a contract |
| `umd+{conid}+{}` | Unsubscribe from a contract |

### Server → client

All outbound messages use a typed JSON envelope:

```json
{"topic": "<name>", "data": <value>}
```

| Topic | Data | When |
|---|---|---|
| `connected` | `true` / `false` | Upstream WebSocket connected or disconnected |
| `authenticated` | `true` / `false` | IBKR `sts` authentication confirmed or lost |
| `batch` | `[{conid, "31":"182.45", …}]` | Tick update for subscribed contracts (batched per `BatchInterval`) |

A newly connected client immediately receives the current `connected` and `authenticated` state so it is never left uninformed.

## Running

```bash
dotnet run --project Feed   # starts on http://localhost:5002 (set in launchSettings.json)
```

Open `http://localhost:5002/demo.html` in a browser for the debug UI.

## Endpoints

| Endpoint | Description |
|---|---|
| `/ws` | Browser WebSocket entry point |
| `/health` | ASP.NET health check — Healthy/Degraded/Unhealthy based on upstream state |
| `/status` | JSON debug snapshot: connection state, subscription details, snapshot cache size, hub client count |
| `/` | JSON service description |
| `/demo.html` | Browser debug UI (static file) |
