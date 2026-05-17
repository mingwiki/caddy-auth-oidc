package caddyauthoidc

import (
	"fmt"
	"strings"
	"time"

	"github.com/caddyserver/caddy/v2"
)

const (
	defaultCookieName         = "caddy_auth_oidc"
	defaultCookiePath         = "/"
	defaultCookieTTL          = caddy.Duration(168 * time.Hour)
	defaultStateTTL           = caddy.Duration(10 * time.Minute)
	defaultHeaderPrefix       = "X-Auth-"
	defaultLogoutRedirect     = "/"
	defaultRefreshLeeway      = caddy.Duration(2 * time.Minute)
	defaultMinRefreshInterval = caddy.Duration(30 * time.Second)
)

var defaultScopes = []string{"openid", "profile", "email"}

func (h *Handler) applyDefaults() {
	if len(h.Scopes) == 0 {
		h.Scopes = append([]string(nil), defaultScopes...)
	}
	if h.CookieName == "" {
		h.CookieName = defaultCookieName
	}
	if h.CookiePath == "" {
		h.CookiePath = defaultCookiePath
	}
	if h.CookieTTL == 0 {
		h.CookieTTL = defaultCookieTTL
	}
	if h.StateTTL == 0 {
		h.StateTTL = defaultStateTTL
	}
	if h.HeaderPrefix == "" {
		h.HeaderPrefix = defaultHeaderPrefix
	}
	if h.LogoutRedirect == "" {
		h.LogoutRedirect = defaultLogoutRedirect
	}
	if h.RefreshLeeway == 0 {
		h.RefreshLeeway = defaultRefreshLeeway
	}
	if h.MinRefreshInterval == 0 {
		h.MinRefreshInterval = defaultMinRefreshInterval
	}
	if h.ForceHTTPSCookie == nil {
		v := true
		h.ForceHTTPSCookie = &v
	}
}

func (h Handler) validate() error {
	if strings.TrimSpace(h.Provider) == "" {
		return fmt.Errorf("provider is required")
	}
	if strings.TrimSpace(h.ClientID) == "" {
		return fmt.Errorf("client_id is required")
	}
	if strings.TrimSpace(h.ClientSecret) == "" {
		return fmt.Errorf("client_secret is required")
	}
	if strings.TrimSpace(h.HeaderPrefix) == "" {
		return fmt.Errorf("header_prefix must not be empty")
	}
	if h.CookieTTL <= 0 {
		return fmt.Errorf("cookie_ttl must be positive")
	}
	if h.StateTTL <= 0 {
		return fmt.Errorf("state_ttl must be positive")
	}
	if h.RefreshLeeway < 0 {
		return fmt.Errorf("refresh_leeway must be non-negative")
	}
	if h.MinRefreshInterval < 0 {
		return fmt.Errorf("min_refresh_interval must be non-negative")
	}
	return nil
}
