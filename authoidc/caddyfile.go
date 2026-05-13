package authoidc

import (
	"strconv"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterHandlerDirective("auth_oidc", parseCaddyfile)
}

func parseCaddyfile(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	var m Handler
	err := m.UnmarshalCaddyfile(h.Dispenser)
	return &m, err
}

func (h *Handler) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		if d.NextArg() {
			return d.ArgErr()
		}

		for d.NextBlock(0) {
			switch d.Val() {
			case "provider":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.Provider = d.Val()
			case "client_id":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.ClientID = d.Val()
			case "client_secret":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.ClientSecret = d.Val()
			case "scopes":
				args := d.RemainingArgs()
				if len(args) == 0 {
					return d.ArgErr()
				}
				h.Scopes = args
			case "cookie_domain":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.CookieDomain = d.Val()
			case "cookie_name":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.CookieName = d.Val()
			case "cookie_path":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.CookiePath = d.Val()
			case "cookie_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid cookie_ttl: %v", err)
				}
				h.CookieTTL = caddy.Duration(dur)
			case "state_ttl":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid state_ttl: %v", err)
				}
				h.StateTTL = caddy.Duration(dur)
			case "inject_headers":
				if d.NextArg() {
					v, err := strconv.ParseBool(d.Val())
					if err != nil {
						return d.Errf("invalid inject_headers: %v", err)
					}
					h.InjectHeaders = v
				} else {
					h.InjectHeaders = true
				}
			case "header_prefix":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.HeaderPrefix = d.Val()
			case "issuer_url":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.IssuerURL = d.Val()
			case "logout_redirect":
				if !d.NextArg() {
					return d.ArgErr()
				}
				h.LogoutRedirect = d.Val()
			case "refresh_leeway":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid refresh_leeway: %v", err)
				}
				h.RefreshLeeway = caddy.Duration(dur)
			case "min_refresh_interval":
				if !d.NextArg() {
					return d.ArgErr()
				}
				dur, err := caddy.ParseDuration(d.Val())
				if err != nil {
					return d.Errf("invalid min_refresh_interval: %v", err)
				}
				h.MinRefreshInterval = caddy.Duration(dur)
			case "force_https_cookie":
				if d.NextArg() {
					v, err := strconv.ParseBool(d.Val())
					if err != nil {
						return d.Errf("invalid force_https_cookie: %v", err)
					}
					h.ForceHTTPSCookie = &v
				} else {
					v := true
					h.ForceHTTPSCookie = &v
				}
			default:
				return d.Errf("unrecognized option: %s", d.Val())
			}
		}
	}
	return nil
}
