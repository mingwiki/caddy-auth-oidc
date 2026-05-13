# Caddy v2 `auth_oidc` Plugin Spec

## Why
Homelab SSO setups often need a simple, native Caddy HTTP middleware for OIDC authentication to avoid running and maintaining an external auth proxy (e.g., oauth2-proxy).

## What Changes
- Add a Caddy v2 HTTP middleware module that performs OIDC login, callback handling, session management, and request authentication.
- Add a stable, minimal Caddyfile directive: `auth_oidc { ... }`.
- Expose built-in endpoints on each protected site:
  - `/auth/login`
  - `/auth/callback`
  - `/auth/logout`
- Use encrypted+signed cookies for:
  - Long-lived session (ID token + refresh token)
  - Short-lived login flow state (CSRF/state + PKCE + return URL)
- Optionally inject a minimal, stable set of OIDC-derived headers upstream.

## Non-Goals
- No “auth portal” UI (only redirects; no custom pages beyond minimal error responses).
- No LDAP/SAML or multi-protocol IAM support.
- No server-side session store (Redis/SQLite/etc).
- No role/group authorization policy engine (authentication only).
- No per-site distinct OIDC client configuration while sharing a cookie (assume one shared OIDC client for all sites that share the cookie domain).

## Impact
- Affected specs: none (new capability).
- Affected code: new Go module and Caddy module registration; no external services required.

## High-Level Architecture
### Caddy integration
- Implement a single Caddy HTTP handler module:
  - Module ID: `http.handlers.auth_oidc`
  - Caddyfile directive: `auth_oidc`
- The handler participates in the HTTP middleware chain:
  - It intercepts requests to `/auth/login`, `/auth/callback`, `/auth/logout`.
  - For all other paths, it enforces authentication:
    - If unauthenticated: redirect to `/auth/login` with a validated “return_to”.
    - If authenticated: optionally inject headers, then call `next`.

### Components (packages)
- `handler`: Caddy handler + routing to auth endpoints.
- `oidc`: provider discovery, verifier, OAuth2 config, token exchange/refresh.
- `session`: securecookie codecs and cookie read/write helpers.
- `redirect`: canonical external URL derivation, safe redirect validation, return-to encoding/decoding.

### Dependencies (must remain minimal)
- `github.com/coreos/go-oidc/v3/oidc`
- `golang.org/x/oauth2`
- `github.com/gorilla/securecookie`
- Standard library only otherwise

## Configuration
### Caddyfile directive (stable)
Default philosophy: secure defaults, minimal knobs, no “framework-like” sub-systems.

Example:
```caddyfile
auth_oidc {
    provider https://id.example.com
    client_id xxx
    client_secret xxx

    cookie_domain .example.com

    scopes openid profile email
    inject_headers true
}
```

#### Supported options (initial)
- `provider <issuer_url>`: OIDC issuer URL used for discovery.
- `client_id <id>`
- `client_secret <secret>`
- `scopes <s1> <s2> ...` (default: `openid profile email`)
- `cookie_domain <domain>` (optional; enables cross-subdomain SSO; supports leading-dot)
- `cookie_name <name>` (default: `caddy_auth_oidc`)
- `cookie_path <path>` (default: `/`)
- `cookie_ttl <duration>` (default: `168h`)
- `state_ttl <duration>` (default: `10m`)
- `inject_headers <bool>` (default: `false`)
- `header_prefix <prefix>` (default: `X-Auth-`)
- `logout_redirect <url-or-path>` (default: `/`)
- `refresh_leeway <duration>` (default: `2m`)
- `min_refresh_interval <duration>` (default: `30s`)
- `force_https_cookie <bool>` (default: `true`)

Notes:
- This spec assumes a single OIDC client config shared across all sites that share the cookie domain.
- Provider must allow multiple redirect URIs if using multiple sites (e.g., `https://app1.example.com/auth/callback`, `https://app2.example.com/auth/callback`).

### JSON config (Caddy API)
- Must mirror Caddyfile options in a single struct with explicit JSON tags.
- Secrets must be treated as sensitive and never logged.

## Runtime Behavior Requirements

### Requirement: Authentication enforcement
The handler SHALL require a valid authenticated session for all requests except the built-in auth endpoints.

#### Scenario: Unauthenticated request to protected path
- **WHEN** a request is made to `/anything` without a valid session cookie
- **THEN** respond `302` redirect to `/auth/login` with a return location for the originally requested URL
- **AND** preserve host and port in computed external URLs

#### Scenario: Authenticated request to protected path
- **WHEN** a request is made with a valid session
- **THEN** call the next handler
- **AND** if header injection is enabled, inject configured headers

### Requirement: `/auth/login`
The handler SHALL initiate the OIDC authorization code flow with PKCE.

#### Scenario: Start login from browser
- **WHEN** a browser requests `/auth/login` (directly or via redirect)
- **THEN** generate state, nonce, and PKCE verifier
- **AND** store them in a short-lived, encrypted+signed cookie (state cookie)
- **AND** redirect to the provider authorization endpoint

### Requirement: `/auth/callback`
The handler SHALL complete the OIDC flow and create a session.

#### Scenario: Successful callback
- **WHEN** the provider redirects back to `/auth/callback` with `code` and `state`
- **THEN** validate `state` against the state cookie (CSRF protection)
- **AND** exchange the authorization code for tokens with timeouts
- **AND** validate the ID token signature and claims via the provider verifier
- **AND** validate `nonce` in the ID token against the state cookie
- **AND** create an encrypted+signed session cookie containing:
  - raw ID token (JWT)
  - refresh token (if issued)
  - expiry time
- **AND** redirect back to the validated `return_to` URL

#### Scenario: Callback validation failure
- **WHEN** state/nonce/token validation fails
- **THEN** clear any flow cookies
- **AND** respond with a minimal error (default: `401` or `403`) and structured logs
- **AND** not leak secrets or raw tokens

### Requirement: Session cookie security
The handler SHALL use an encrypted+signed cookie to store session data.

#### Cookie properties (defaults)
- `HttpOnly: true`
- `Secure: true` (or forced if `force_https_cookie=true`)
- `SameSite: Lax`
- `Path: /`
- `Domain: <cookie_domain>` if configured, else host-only

### Requirement: JWT validation and refresh
The handler SHALL validate session freshness and refresh when possible.

#### Scenario: Session valid and unexpired
- **WHEN** an incoming request has a session cookie with an unexpired ID token
- **THEN** validate the ID token signature and essential claims (issuer, audience, exp, iat)

#### Scenario: Session near expiry with refresh token
- **WHEN** the ID token is within `refresh_leeway` of expiry AND a refresh token exists
- **THEN** attempt a token refresh using the provider token endpoint
- **AND** rate-limit refresh attempts per-process using `min_refresh_interval`
- **AND** update the session cookie on success
- **AND** if refresh fails, treat as unauthenticated and redirect to login

### Requirement: Header injection (optional)
If enabled, the handler SHALL inject a stable, minimal set of headers derived from the validated ID token claims.

#### Injected headers (initial set)
- `<prefix>Subject`: `sub`
- `<prefix>Email`: `email` (if present)
- `<prefix>Name`: `name` or `preferred_username` (if present)
- `<prefix>Issuer`: `iss`
- `<prefix>Claims`: base64url-encoded JSON of the full decoded claim set (bounded by a reasonable size limit)

The handler SHALL:
- overwrite existing headers with the same names
- never inject refresh tokens or access tokens as headers
- strip/normalize invalid header bytes

### Requirement: `/auth/logout`
The handler SHALL clear the session cookie and optionally perform provider logout.

#### Scenario: Local logout
- **WHEN** a browser requests `/auth/logout`
- **THEN** clear session cookie (and any flow cookies)
- **AND** redirect to `logout_redirect` (validated)

#### Scenario: Provider end-session support (best effort)
- **WHEN** the provider metadata includes an end-session endpoint
- **THEN** redirect the browser to it with:
  - `id_token_hint` (if available)
  - `post_logout_redirect_uri` (if supported)

### Requirement: Secure redirect validation
The handler SHALL only redirect to:
- a relative path on the same host, OR
- an absolute URL whose host matches the current request host

The handler SHALL reject:
- `//evil.com`-style redirects
- mismatched host redirects
- invalid URL encodings

### Requirement: Reverse proxy deployments and “external URL”
The handler SHALL derive the “external URL” (scheme + host + optional port) from Caddy request context in a way that:
- preserves the original port
- supports deployments behind an L4/L7 proxy (when Caddy is configured appropriately)

Implementation SHALL prefer Caddy-provided request variables/replacer values over ad-hoc parsing of `X-Forwarded-*` headers.

## Logging and Observability
- Use structured logs via Caddy’s logger:
  - include request host, path, auth outcome (ok/redirect/deny), and error class
  - never log raw tokens, client secrets, or cookie values
- Keep error responses minimal for browsers; detailed info in logs.

## Security Considerations (must document + implement)
- PKCE, state, and nonce are mandatory.
- Session cookie is always encrypted+signed.
- Constant-time comparisons where applicable (state).
- Timeouts for OIDC discovery, token exchange, refresh, and JWKS retrieval.
- Limit claim/header sizes to avoid header bloat and upstream issues.
- Harden redirect validation (no open redirects).
- Respect clock skew with small leeway.
- Avoid accepting tokens with unexpected algorithms.

## Production Hardening Recommendations (README)
- Run behind HTTPS; keep `force_https_cookie=true`.
- Configure the provider with all callback URLs used by sites.
- Keep cookie_domain as narrow as possible.
- Set Caddy `trusted_proxies` appropriately when behind a proxy.
- Rotate OIDC client secrets and cookie keys (requires session invalidation).
- Use distinct upstream header prefixes to avoid collisions.

## Project Structure (planned)
Repository (initial):
- `go.mod`, `go.sum`
- `authoidc/`
  - `handler.go` (Caddy handler)
  - `caddyfile.go` (Caddyfile parser)
  - `config.go` (config structs + validation)
  - `oidc.go` (provider discovery, verifier, oauth2 config)
  - `session.go` (securecookie encode/decode + cookie IO)
  - `endpoints.go` (login/callback/logout handlers)
  - `redirect.go` (external URL and safe redirect helpers)
- `README.md`
- `Dockerfile` (xcaddy build example)
- `examples/` (Caddyfile examples)
- `tests/` (Go tests for redirect validation, cookie/session encode/decode, and handler flows where feasible)

