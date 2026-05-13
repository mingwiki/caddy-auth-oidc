# Checklist
- [x] Caddy module ID is `http.handlers.auth_oidc` and directive `auth_oidc` parses as specified
- [x] `/auth/login` implements state + nonce + PKCE and sets only short-lived flow cookies
- [x] `/auth/callback` validates state/nonce, exchanges code, verifies ID token, and creates a session cookie
- [x] Session cookie is encrypted+signed and uses secure defaults (HttpOnly/Secure/SameSite)
- [x] Requests to protected paths redirect to login when unauthenticated and pass through when authenticated
- [x] Redirect validation prevents open redirect attacks (relative or same-host only)
- [x] “External URL” derivation preserves host + port and works with Caddy request context
- [x] Header injection (when enabled) injects only the specified headers and enforces size limits
- [x] Refresh flow updates the cookie when nearing expiry and fails gracefully to re-login
- [x] Logout clears cookies and optionally uses provider end-session endpoint (best effort)
- [x] Structured logs exist for auth decisions and failures without leaking secrets/tokens
- [x] README includes: config reference, examples, xcaddy build, Docker build, security considerations, hardening recommendations
- [x] Go tests cover redirect validation and cookie/session encode/decode (and other pure logic where feasible)

