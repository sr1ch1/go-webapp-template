[![GitHub Workflow Status](https://img.shields.io/github/actions/workflow/status/sr1ch1/go-webapp-template/ci.yml)](https://github.com/sr1ch1/go-webapp-template/actions?query=branch%3Amain)
[![Coverage Status](https://img.shields.io/codecov/c/github/sr1ch1/go-webapp-template)](https://app.codecov.io/github/sr1ch1/go-webapp-template)
![GitHub go.mod Go version](https://img.shields.io/github/go-mod/go-version/sr1ch1/go-webapp-template)
[![GitHub](https://img.shields.io/github/license/sr1ch1/go-webapp-template)](https://opensource.org/licenses/MIT)
# Web App Template

A Go template for internal web applications that sit behind an external,
zero-trust Identity Provider. The provider authenticates callers and issues
signed JWTs; this application verifies the JWT on every request and derives
identity (the **Principal**) and **roles** from it. Cloudflare Access is the
default provider; others plug in via a compile-time registry.

## Quickstart

Requires [mise](https://mise.jdx.dev/) (installs the pinned Go toolchain) and
a C compiler for cgo: clang (Xcode Command Line Tools) on macOS, gcc on
Linux. On Windows, mise installs zig instead — `mise run build` forwards to
`zig cc` automatically.

```sh
mise install

export APP_AUTH_CLOUDFLARE_TEAM_DOMAIN="yourteam"     # https://yourteam.cloudflareaccess.com
export APP_AUTH_CLOUDFLARE_AUDIENCE="your-aud-tag"    # Access application AUD tag

go run ./cmd/app
```

Then browse through your Access-protected hostname. The app listens on
`:8080` by default and creates `app.db` in the working directory.

Build a binary for the current platform into `bin/`:

```sh
mise run build
```

On Windows without using the mise task, set `CGO_ENABLED=1` and use
`scripts/cc_zig.py` as the cgo compiler wrapper:

```bat
set CGO_ENABLED=1
set CC=python scripts\cc_zig.py
go build -o bin\app.exe .\cmd\app
```

Checks (gofmt + go vet + go test -race):

```sh
mise run check
```

## Configuration reference

All configuration is environment-only, with the `APP_` prefix. The app fails
fast at startup when a required value is missing or malformed.

| Variable | Default | Required | Meaning |
|---|---|---|---|
| `APP_HTTP_ADDR` | `:8080` | optional | Listen address |
| `APP_HTTP_READ_HEADER_TIMEOUT` | `5s` | optional | http.Server ReadHeaderTimeout |
| `APP_HTTP_READ_TIMEOUT` | `10s` | optional | http.Server ReadTimeout |
| `APP_HTTP_WRITE_TIMEOUT` | `30s` | optional | http.Server WriteTimeout |
| `APP_HTTP_IDLE_TIMEOUT` | `60s` | optional | http.Server IdleTimeout |
| `APP_HTTP_SHUTDOWN_TIMEOUT` | `15s` | optional | Graceful shutdown drain budget |
| `APP_HTTP_DISABLE_HSTS` | `false` | optional | Omit the Strict-Transport-Security header (useful for local HTTP dev) |
| `APP_AUTH_PROVIDER` | `cloudflare-access` | optional | Provider registry key |
| `APP_AUTH_CLOUDFLARE_TEAM_DOMAIN` | — | with cloudflare-access | Team domain (`<team>.cloudflareaccess.com`) |
| `APP_AUTH_CLOUDFLARE_AUDIENCE` | — | with cloudflare-access | Access application AUD tag |
| `APP_DATABASE_PATH` | `app.db` | optional | SQLite file path |
| `APP_LOG_LEVEL` | `info` | optional | slog level (debug/info/warn/error) |

Durations are Go duration strings (`500ms`, `10s`, `1m`).

## Security model

**Trust boundary.** In the default deployment, Cloudflare terminates TLS at
the edge and attaches the caller's identity as a JWT header. The application
still verifies the JWT on every request — signature against the provider's
JWKS (cached ~15 min, refreshed on unknown key IDs), pinned algorithm
(never the token's `alg`), expiry, issuer, and audience. Trusting the tunnel
alone would make the app one misconfigured route away from unauthenticated
access; defense in depth is cheap here.

**Tokens are never logged.** The JWT header value is never written to logs,
at any level, including error paths. Verification failures log only a
generic reason (e.g. "token expired"), never token material.

**JWT verification is narrow and pinned.** Signature verification and claims
validation are delegated to `github.com/golang-jwt/jwt/v5` — a zero-dependency
library, pinned and checksummed in `go.sum`. The verifier supports only the
RS256 and ES256 algorithms, pins the algorithm from config (never the token's
`alg`, rejecting `alg: none` and `alg: HS256` confusion before signature
verification), and validates issuer, audience, expiry, and subject. The JWKS
client (caching, refresh on unknown key IDs, bounded response, fetch timeout)
remains our own code.

**Vague auth errors.** Callers get a generic 401 or 403 problem details
response (`application/problem+json`) with no detail; the specific cause is
logged server-side only. Failure-oracle resistance beats caller convenience
for internal apps.

**CSRF.** There are no cookies, but the tunnel attaches the identity header
to *any* browser request to the app's origin — including cross-site ones a
victim's browser is tricked into making. Same-origin checks on cookies do
not apply, so mutations (non-GET/HEAD) must carry a custom header a
cross-site form cannot set (`X-Requested-With: fetch`, or htmx's
`HX-Request: true`), and Fetch Metadata (`Sec-Fetch-Site`) is honored when
the browser sends it.

**Rate limiting.** Admin mutations are rate-limited per authenticated
subject using an in-memory token bucket. The limiter also bounds its own
memory by evicting stale and least-recently-used buckets.

**Strict CSP.** `default-src 'self'` with no `unsafe-inline` and no
`unsafe-eval`: all JS/CSS are external files under `/static/`. htmx runs
with `allowEval = false` and `selfRequestsOnly = true`. Note that a strict
CSP only *limits* the protection against injected `hx-*` attributes (an
attacker who can inject HTML can point htmx at application endpoints);
`selfRequestsOnly` keeps those requests same-origin, and the CSRF header
requirement still applies to mutations. The Alpine.js CSP build is used so
no `unsafe-eval` is needed.

## Deriving your own app

```sh
gonew github.com/sr1ch1/go-webapp-template example.com/yourapp
```

Rename checklist:

1. Module path: `gonew` rewrites `go.mod` and imports for you.
2. Binary/command name in `cmd/app` if you want a different one.
3. Provider config: set your own `APP_AUTH_*` values; add a provider if you
   are not behind Cloudflare Access (below).
4. Seed rows in `internal/store/migrations/0001_config.up.sql` and the
   templates/static assets under `web/`.

## Adding an Identity Provider

Providers are registered at compile time — no dynamic loading. To add one:

1. Create `internal/auth/<name>.go` with a constructor. Most providers are
   JWT-based: build on `auth.NewJWTProvider`, supplying the header name,
   issuer, audience, pinned algorithm (`RS256` or `ES256`), JWKS URL, and a
   `MapClaims` function.
2. Add one `register("<name>", ...)` entry in that file's `init`.
3. Accept its settings via `APP_AUTH_*` env vars in `internal/config` and
   select it with `APP_AUTH_PROVIDER=<name>`.

## Roles and role mapping

Roles are strings asserted by the Identity Provider in the JWT (Cloudflare
Access: the custom `roles` claim, an array of strings). The app maps them
onto routes with `auth.RequireRole("admin")` — the template uses `admin` for
Runtime Configuration mutations.

Each provider owns a **role-mapping function** hook that normalizes the
provider's role naming into the app's canonical format (e.g. lowercasing,
stripping a prefix). The default is the identity function; pass your own
`RoleMapper` to the provider constructor when the IdP's naming differs from
the app's.

## Test Identity Provider

A `test` provider is built in for browser-based end-to-end tests. It uses the
same JWT verifier as production but points at a local JWKS server. Select it
with:

```sh
APP_AUTH_PROVIDER=test \
APP_AUTH_TEST_ISSUER=https://test.example.com \
APP_AUTH_TEST_AUDIENCE=test-audience \
APP_AUTH_TEST_JWKS_URL=http://localhost:9999/jwks.json \
go run ./cmd/app
```

Optional: `APP_AUTH_TEST_HEADER` (default `Cf-Access-Jwt-Assertion`) and
`APP_AUTH_TEST_ALGORITHM` (default `RS256`).

## Browser end-to-end tests

End-to-end tests live in `e2e/` and use Playwright. Install dependencies and
browsers once:

```sh
mise run e2e-setup
```

Run the suite:

```sh
mise run e2e
```

The global setup builds the app, starts a local JWKS server, and signs tokens
for admin and non-admin users. The tests exercise real JWT verification, htmx
fragments, and the strict CSP.

## Frontend vendoring

htmx and Alpine.js (CSP build) are vendored under `web/static/vendor/`,
pinned by version and SHA-256. To refresh:

```sh
mise run vendor-frontend
```

Update the URLs and expected checksums in `mise.toml` when bumping versions.
htmx is pinned to **2.x**: htmx 4 is in beta with breaking changes ahead,
while 2.x is supported in perpetuity. The hypermedia surface is kept small on
purpose to bound a future upgrade.

## Database

SQLite via `github.com/mattn/go-sqlite3` (cgo, zero transitive dependencies;
the SQLite amalgamation ships inside the pinned module), in WAL
mode. Migrations are embedded SQL files under
`internal/store/migrations/NNNN_name.up.sql`, applied in lexicographic order
at startup and recorded in `schema_migrations`. Migrations are **up-only**: 
reversals are new up migrations, and the app refuses to start
when the database is newer than the binary.

## Metrics

`GET /metrics` serves Prometheus-format metrics without authentication, next
to `/healthz` and `/readyz`: request counts and latency histograms labeled by
method, route pattern, and status code, an in-flight gauge, and Go runtime
gauges. The registry in `internal/metrics` is stdlib-only and renders the
text exposition format by hand — point Prometheus (or any compatible
scraper) at the endpoint. Route patterns keep label cardinality bounded; the
series carry no caller data. The request metrics cover only the authenticated
chain; unauthenticated routes (`/healthz`, `/readyz`, `/metrics`, `/static/*`)
are not recorded.

## Deployment

Build a container image locally:

```sh
docker build -t go-webapp-template .
```

Or run the compose stack with a `.env` file containing your Identity Provider
settings:

```sh
# .env
APP_AUTH_PROVIDER=cloudflare-access
APP_AUTH_CLOUDFLARE_TEAM_DOMAIN=yourteam
APP_AUTH_CLOUDFLARE_AUDIENCE=your-aud-tag
APP_LOG_LEVEL=info
```

```sh
docker compose up --build
```

The image runs as a non-root user and stores the SQLite database at `/data/app.db`.
Mount a volume at `/data` for persistence.

The binary exposes build metadata at `GET /api/version` (authenticated) and
unauthenticated `/healthz`, `/readyz`, and `/metrics` probes.

## Server-Sent Events

SSE works through the middleware chain: the logging/metrics status wrapper
forwards `http.Flusher` and implements `Unwrap`, so both
`w.(http.Flusher).Flush()` and `http.NewResponseController(w).Flush()`
behave as expected. Two timeout behaviors matter before you write an SSE
handler:

- **`APP_HTTP_WRITE_TIMEOUT` is absolute, not per-write.** net/http sets the
  write deadline once when the request starts; writing more data does *not*
  extend it. With the 30s default, every SSE stream is cut off after 30
  seconds — and keep-alive frames do not reset it. To hold a stream open,
  extend the deadline from the handler before each flush:

  ```go
  rc := http.NewResponseController(w)
  // before writing each event:
  _ = rc.SetWriteDeadline(time.Now().Add(30 * time.Second))
  fmt.Fprintf(w, "data: %s\n\n", payload)
  _ = rc.Flush()
  ```

  Setting `APP_HTTP_WRITE_TIMEOUT=0` disables the timeout entirely, but for
  *all* responses — per-event deadlines are the tighter option.

- **Intermediary idle timeouts are a different clock.** Cloudflare closes
  proxied connections that carry no traffic after ~100 seconds; other
  proxies behave similarly. This is what keep-alive frames are for: send an
  SSE comment line (`: ping\n\n`) every 30s or so when there is no event
  traffic. Keep-alives also surface dead clients promptly — the write fails
  and the handler can return — instead of leaking a goroutine that only
  notices when the next real event arrives. Either way, always select on
  `r.Context().Done()` and return when it fires.

## Scaling limits

This template is designed for a **single running instance**:

- The rate limiter stores buckets in process memory, so two replicas give each
  subject twice the allowed burst.
- SQLite is configured with a single writer (`SetMaxOpenConns(1)`) and is tied
  to a local file.

For a small internal admin tool these limits are usually fine. Outgrow them by
moving to PostgreSQL and a shared rate-limit backend (Redis, memcached, or a
database table), and running multiple stateless replicas behind a load
balancer.
