# Caddy Auth OIDC Plugin

A modern, minimal, and native Caddy v2 authentication plugin for generic OIDC providers (e.g. Pocket ID, Keycloak, Authentik).
It replaces the need for external auth proxies like `oauth2-proxy` in simple homelab SSO setups.

## Features

- **Native Caddy HTTP Middleware:** Integrates directly into Caddy.
- **Generic OIDC Support:** Works with any standard OpenID Connect provider.
- **Encrypted Session Cookies:** Uses `gorilla/securecookie` to encrypt and sign session data.
- **PKCE Support:** Modern OAuth2 authorization code flow with PKCE and state/nonce validation.
- **Multi-Domain SSO:** Optionally share authentication state across multiple subdomains.
- **Token Refresh:** Automatically refreshes the session near expiry.
- **Header Injection:** Optionally pass user claims upstream.

## Getting Started

### Building with `xcaddy`

The easiest way to build Caddy with this plugin is using `xcaddy`:

```bash
xcaddy build \
    --with github.com/mingwiki/caddy-auth-oidc
```

### Docker Build Example

```dockerfile
FROM caddy:2-builder AS builder

RUN xcaddy build \
    --with github.com/mingwiki/caddy-auth-oidc

FROM caddy:2

COPY --from=builder /usr/bin/caddy /usr/bin/caddy
```

## Caddyfile Configuration

### Simple Single-Site

```caddyfile
auth_oidc {
    provider https://id.example.com
    client_id my_client
    client_secret my_secret
}

reverse_proxy localhost:8080
```

### Advanced Multi-Subdomain SSO

This configuration shares a single OIDC client and session cookie across multiple sites:

```caddyfile
(auth) {
    auth_oidc {
        provider https://id.example.com
        client_id my_client
        client_secret my_secret

        cookie_domain .example.com
        scopes openid profile email

        inject_headers true
        header_prefix X-Auth-
    }
}

app1.example.com {
    import auth
    reverse_proxy localhost:8081
}

app2.example.com {
    import auth
    reverse_proxy localhost:8082
}
```

## Configuration Reference

| Option | Description | Default |
|--------|-------------|---------|
| `provider` | OIDC issuer URL (required) | |
| `client_id` | OAuth2 Client ID (required) | |
| `client_secret` | OAuth2 Client Secret (required) | |
| `scopes` | OAuth2 scopes | `openid profile email` |
| `cookie_domain` | Domain for the session cookie | *none* |
| `cookie_name` | Name of the session cookie | `caddy_auth_oidc` |
| `cookie_path` | Path for the session cookie | `/` |
| `cookie_ttl` | Duration the session cookie is valid | `168h` (7 days) |
| `state_ttl` | Duration the flow state cookie is valid | `10m` |
| `inject_headers` | Inject user claims as headers upstream | `false` |
| `header_prefix` | Prefix for injected headers | `X-Auth-` |
| `logout_redirect` | URL to redirect to after logout | `/` |
| `refresh_leeway` | Time before expiry to attempt token refresh | `2m` |
| `force_https_cookie` | Force the `Secure` flag on cookies | `true` |

## Endpoints

The plugin automatically handles the following routes on the protected site:

- `/auth/login`: Initiates the OIDC flow.
- `/auth/callback`: Handles the OIDC callback.
- `/auth/logout`: Clears the local session and optionally redirects to the provider's end-session endpoint.

## Security Considerations & Hardening

- **Use HTTPS:** Run Caddy with HTTPS enabled. The plugin defaults to forcing the `Secure` flag on cookies.
- **Provider Configuration:** Ensure the OIDC provider is configured to accept callback URLs for *all* subdomains using the plugin (e.g. `https://app1.example.com/auth/callback`, `https://app2.example.com/auth/callback`).
- **Cookie Domain:** Keep the `cookie_domain` as narrow as possible. Use a leading dot (e.g. `.example.com`) to cover subdomains.
- **Reverse Proxies:** If running Caddy behind another reverse proxy, ensure `trusted_proxies` is configured correctly so Caddy knows the original protocol and host.
- **Secrets:** Treat the `client_secret` with care. The plugin uses it to derive encryption and signing keys for the session cookie. Rotating the `client_secret` will invalidate all active sessions.

## Development Guide

If you want to modify this plugin or build it from local source code, follow these steps:

### Prerequisites

- Go 1.22 or higher
- [xcaddy](https://github.com/caddyserver/xcaddy) installed (`go install github.com/caddyserver/xcaddy/cmd/xcaddy@latest`)

### Running Tests

The project includes unit tests for session codecs and redirect URL validation.

```bash
go test -v ./...
```

### Building for Local Testing

To test your local changes, use `xcaddy` and replace the module path with your local directory:

```bash
xcaddy build \
    --with github.com/mingwiki/caddy-auth-oidc=./
```

This will produce a `caddy` executable in your current directory with your local plugin modifications compiled in.

### Running the Local Build

Create a `Caddyfile` for testing and run the newly built binary:

```bash
./caddy run --config Caddyfile
```