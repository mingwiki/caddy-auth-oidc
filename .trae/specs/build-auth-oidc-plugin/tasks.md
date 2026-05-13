# Tasks
- [x] Task 1: Define module surface and configuration
  - [x] Finalize config fields and defaults (Caddy JSON + Caddyfile)
  - [x] Define stable header injection contract and size limits
  - [x] Define redirect validation rules and test cases

- [x] Task 2: Implement core handler skeleton
  - [x] Register `http.handlers.auth_oidc` module
  - [x] Implement middleware `ServeHTTP` authentication gate
  - [x] Implement endpoint routing for `/auth/login`, `/auth/callback`, `/auth/logout`

- [x] Task 3: Implement OIDC discovery + verifier + OAuth2 flow
  - [x] Provider discovery with timeouts
  - [x] OAuth2 config + PKCE support
  - [x] ID token verification (issuer/audience/exp/nonce)

- [x] Task 4: Implement cookie-backed session + flow state
  - [x] Securecookie codecs (encryption + signing keys)
  - [x] Flow state cookie (state/nonce/pkce/return_to) with TTL
  - [x] Session cookie (id_token/refresh_token/expiry) with TTL and secure defaults

- [x] Task 5: Implement refresh + logout
  - [x] Refresh on request when within leeway; enforce min refresh interval
  - [x] Local logout (clear cookies)
  - [x] Provider end-session redirect (best-effort)

- [x] Task 6: Tests and docs
  - [x] Unit tests: redirect validation, cookie encode/decode, header injection sanitation/limits
  - [x] README: usage, Caddyfile examples, xcaddy build, Docker build, security notes, hardening notes
  - [x] Examples: single-site, multi-subdomain SSO with cookie_domain, behind-proxy notes

# Task Dependencies
- Task 2 depends on Task 1
- Task 3 depends on Task 2
- Task 4 depends on Task 2
- Task 5 depends on Task 3 and Task 4
- Task 6 depends on Tasks 2-5
