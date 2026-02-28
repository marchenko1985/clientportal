# Nginx Configuration

nginx provides TLS termination, rate limiting, caching, WebSocket proxying,
and basic auth for two .NET services:

- **gateway** (localhost:5001) — IBKR REST API proxy (Gateway or CookieGateway)
- **feed** (localhost:5002) — WebSocket multiplexer (Feed)

## Directory layout

conf.d/
cache.conf proxy_cache_path (shared cache zone)
clientportal.conf upstream blocks: gateway (5001), feed (5002)
gzip.conf gzip compression settings
ratelimit.conf limit_req_zone (shared rate-limit zone)
security.conf server_tokens off, client_max_body_size
websockets.conf $connection_upgrade map for WebSocket proxying
snippets/
cache1d.conf include to cache responses 1 day
cache1h.conf include to cache responses 1 hour (reference example)
clientportal.conf shared proxy headers + timeouts (NO proxy_pass — caller sets it)
ratelimit.conf include to apply the global IBKR rate limit
security-headers.conf HSTS, X-Frame-Options, X-Content-Type-Options
sites-available/
clientportal.conf vhost: routing, TLS, auth, all location blocks

Symlink to enable: ln -s /etc/nginx/sites-available/clientportal.conf /etc/nginx/sites-enabled/

## Routes

| Path                            | Auth       | Backend         | Notes                      |
| ------------------------------- | ---------- | --------------- | -------------------------- |
| `/v1/api/ws`                    | —          | blocked         | 403 — use /ws instead      |
| `/v1/api/iserver/secdef/search` | —          | gateway         | rate-limited, cached 1 day |
| `/v1/api/`                      | —          | gateway         | rate-limited               |
| `/ws`                           | —          | feed            | WebSocket, 1h timeouts     |
| `/gateway/health`               | —          | gateway /health | public health check        |
| `/feed/health`                  | —          | feed /health    | public health check        |
| `/session`                      | basic auth | gateway         | JSON session state         |
| `/status`                       | basic auth | feed            | feed status page           |
| `/`                             | basic auth | gateway         | Razor Pages status page    |
| (everything else)               | —          | gateway         | returns 404                |

## Rate limiting

IBKR enforces 10 r/s per account. Zone key is `""` (global bucket, not per-IP) so all
clients together stay under IBKR's limit. burst=1000 delay=1000 means up to 1000 requests
queue; none are rejected immediately. Worst-case queue: 100s. proxy_read_timeout=120s.

## Caching

Only `/v1/api/iserver/secdef/search` is cached (1 day). Cache key = `$request_uri`.
proxy_cache_lock prevents stampede on cache miss. X-Cache-Status header shows HIT/MISS.
cache1h.conf exists as a reference for adding more cached endpoints in future.

## add_header inheritance

Any location with its own add_header MUST include snippets/security-headers.conf explicitly,
because nginx's inheritance rule drops parent add_headers when a child has any of its own.
The cache snippets already include security-headers.conf for this reason.

## Basic authentication

```bash
htpasswd -c /etc/nginx/.htpasswd admin    # create (first user)
htpasswd /etc/nginx/.htpasswd user2       # add more users
```

## Deployment

```bash
nginx -t         # validate
nginx -s reload  # reload without downtime
```
