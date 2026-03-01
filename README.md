![Interactive Brokers](https://ndcdyn.interactivebrokers.com/images/common/logos/ibkr/interactive-brokers.svg)

# ClientPortal

IBKR reverse proxy suite — .NET 10. Manages IBKR credentials so callers talk to a plain API without any auth logic on their side.

If hosted at `https://example.com`.

Instead of calling `https://api.ibkr.com/v1/api/iserver/secdef/search?symbol=AAPL`, simply call:

```
https://example.com/v1/api/iserver/secdef/search?symbol=AAPL
```

## Projects

| Project                                  | Auth method                 | Notes                                              |
| ---------------------------------------- | --------------------------- | -------------------------------------------------- |
| [Gateway](Gateway/README.md)             | OAuth 1.0 (RSA-SHA256 + DH) | Requires IBKR OAuth application registration       |
| [CookieGateway](CookieGateway/README.md) | Username/password (SRP-6)   | Preferred — cookie auth matches IBKR's web UI      |
| [Feed](Feed/README.md)                   | —                           | WebSocket multiplexer: one upstream → many clients |

Both gateways run on port 5001 and expose the same proxied routes.

## Quick start

```bash
dotnet run --project CookieGateway   # or: dotnet run --project Gateway
```

Wait for the session initialized log line, then run smoke tests:

```bash
# Returns conid of AAPL — confirms search is working
curl -s 'http://localhost:5001/v1/api/iserver/secdef/search?symbol=AAPL' | jq -r '.[0].conid'
# expected: 265598

# Returns most recent closing price — confirms history is working
curl -s 'http://localhost:5001/v1/api/iserver/marketdata/history?conid=265598&bar=1d&period=1w' | jq -r '.data[-1].c'
# expected: a price like 272.95
```

## API Endpoints

### Search

Find a `conid` by symbol.

```http
GET /v1/api/iserver/secdef/search?symbol=AAPL
```

```json
[
  {
    "conid": "265598",
    "companyHeader": "APPLE INC - NASDAQ",
    "companyName": "APPLE INC",
    "symbol": "AAPL",
    "sections": [{ "secType": "STK" }, { "secType": "OPT", "months": "MAR26;APR26;MAY26;..." }]
  }
]
```

### History

Retrieve historical prices.

```http
GET /v1/api/iserver/marketdata/history?conid=265598&bar=1d&period=1y
```

```json
{
  "symbol": "AAPL",
  "data": [{ "o": 241.81, "c": 238.03, "h": 244.03, "l": 236.11, "v": 247710.55, "t": 1741012200000 }],
  "points": 249
}
```

Note: you may occasionally receive a non-200 response with `{"error":"Chart data is not available"}` — this is transient, retry once.

### Snapshot

Retrieve real-time snapshot data for one or more contracts.

```http
GET /v1/api/iserver/marketdata/snapshot?conids=265598&fields=31,81
```

```json
[{ "conid": 265598, "31": "263.55" }]
```

Notes:

- See [FIELDS.md](https://github.com/options-lab-info/optionslab/blob/main/clientportal/FIELDS.md) for field codes.
- The first call acts as a preflight — IBKR creates the subscription and returns no data. Call again after a moment to get values.
- Batch limit: max 100 conids per request.

### Strikes

Get available strikes for an options contract.

```http
GET /v1/api/iserver/secdef/strikes?conid=265598&sectype=OPT&month=MAR26
```

```json
{
  "call": [90.0, 95.0, "...", 450.0],
  "put": [90.0, 95.0, "...", 450.0]
}
```

Available months are returned in the `sections` array of the Search response.

### Info

Get contract details for a specific option (useful for building option chains).

```http
GET /v1/api/iserver/secdef/info?conid=265598&sectype=OPT&month=MAR26&strike=240.0&right=C
```

```json
[
  {
    "conid": 855006149,
    "symbol": "AAPL",
    "secType": "OPT",
    "right": "C",
    "strike": 240.0,
    "maturityDate": "20260302",
    "multiplier": "100"
  }
]
```

Notes:

- Omit `right` to retrieve both calls and puts.
- Pass `strike=0` to retrieve all strikes.

## Option Chain Example

Full flow to build an option chain for AAPL March 2026:

**1. Find conid and available months**

```http
GET /v1/api/iserver/secdef/search?symbol=AAPL
```

From the response, extract `conid` (`265598`) and option months from the `OPT` section.

**2. Fetch all option contracts for the month**

```http
GET /v1/api/iserver/secdef/info?conid=265598&sectype=OPT&month=MAR26&strike=0
```

Returns all calls and puts for the month with their individual conids.

**3. Fetch snapshot data**

```http
GET /v1/api/iserver/marketdata/snapshot?conids=855005998,855006015&fields=31,84,86
```

Where `31` = last price, `84` = bid, `86` = ask. First call is a preflight; repeat after a moment for data.

## IBKR API Reference

- [Reference](https://www.interactivebrokers.com/campus/ibkr-api-page/webapi-ref/)
- [Changelog](https://www.interactivebrokers.com/campus/ibkr-api-page/web-api-changelog/)
