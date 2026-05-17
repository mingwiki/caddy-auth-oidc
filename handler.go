package caddyauthoidc

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/securecookie"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func init() {
	caddy.RegisterModule(Handler{})
}

type Handler struct {
	Provider string `json:"provider,omitempty"`

	// IssuerURL overrides the issuer URL for OIDC provider validation.
	// Use this when the discovery URL differs from the issuer URL in the
	// provider's metadata (e.g. discovering via localhost but validating
	// against the external domain).
	IssuerURL string `json:"issuer_url,omitempty"`

	ClientID     string `json:"client_id,omitempty"`
	ClientSecret string `json:"client_secret,omitempty"`

	Scopes []string `json:"scopes,omitempty"`

	CookieDomain string         `json:"cookie_domain,omitempty"`
	CookieName   string         `json:"cookie_name,omitempty"`
	CookiePath   string         `json:"cookie_path,omitempty"`
	CookieTTL    caddy.Duration `json:"cookie_ttl,omitempty"`
	StateTTL     caddy.Duration `json:"state_ttl,omitempty"`

	InjectHeaders bool   `json:"inject_headers,omitempty"`
	HeaderPrefix  string `json:"header_prefix,omitempty"`

	LogoutRedirect string `json:"logout_redirect,omitempty"`

	RefreshLeeway      caddy.Duration `json:"refresh_leeway,omitempty"`
	MinRefreshInterval caddy.Duration `json:"min_refresh_interval,omitempty"`

	ForceHTTPSCookie *bool `json:"force_https_cookie,omitempty"`

	logger       *zap.Logger
	flowCodec    *securecookie.SecureCookie
	sessionCodec *securecookie.SecureCookie

	provider     *oidc.Provider
	verifier     *oidc.IDTokenVerifier
	oauth2Config oauth2.Config
}

func (Handler) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.auth_oidc",
		New: func() caddy.Module { return new(Handler) },
	}
}

func (h *Handler) Provision(ctx caddy.Context) error {
	h.logger = ctx.Logger(h)
	h.applyDefaults()
	if err := h.validate(); err != nil {
		return err
	}
	if err := h.initCookieCodecs(); err != nil {
		return err
	}
	return h.initOIDC(ctx.Context)
}

func (h Handler) Validate() error {
	return h.validate()
}

func (h Handler) ServeHTTP(w http.ResponseWriter, r *http.Request, next caddyhttp.Handler) error {
	switch r.URL.Path {
	case "/auth/login":
		return h.serveLogin(w, r)
	case "/auth/callback":
		return h.serveCallback(w, r)
	case "/auth/logout":
		return h.serveLogout(w, r)
	}

	if sess, ok := h.hasSessionCookie(w, r); ok {
		if h.InjectHeaders {
			h.injectHeaders(r, sess.IDToken)
		}
		return next.ServeHTTP(w, r)
	}

	loginURL := url.URL{Path: "/auth/login"}
	q := loginURL.Query()
	q.Set("return_to", r.URL.RequestURI())
	loginURL.RawQuery = q.Encode()
	http.Redirect(w, r, loginURL.String(), http.StatusFound)
	return nil
}

func (h Handler) hasSessionCookie(w http.ResponseWriter, r *http.Request) (sessionData, bool) {
	sess, err := h.readSessionCookie(r)
	if err != nil {
		return sessionData{}, false
	}

	// Check if refresh is needed
	if sess.RefreshToken != "" && time.Until(sess.ExpiresAt) < time.Duration(h.RefreshLeeway) {
		h.logger.Debug("session near expiry, attempting refresh")

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()

		token := &oauth2.Token{RefreshToken: sess.RefreshToken}
		tokenSource := h.oauth2Config.TokenSource(ctx, token)
		newToken, err := tokenSource.Token()
		if err != nil {
			h.logger.Warn("token refresh failed", zap.Error(err))
			return sessionData{}, false // Force re-login
		}

		if newToken.AccessToken != token.AccessToken || newToken.RefreshToken != token.RefreshToken {
			rawIDToken, ok := newToken.Extra("id_token").(string)
			if ok {
				// Verify the new ID token
				if idToken, err := h.verifier.Verify(ctx, rawIDToken); err == nil {
					sess.IDToken = rawIDToken
					if newToken.RefreshToken != "" {
						sess.RefreshToken = newToken.RefreshToken
					}
					sess.ExpiresAt = idToken.Expiry

					if err := h.setSessionCookie(w, r, sess); err != nil {
						h.logger.Error("failed to set refreshed session cookie", zap.Error(err))
					} else {
						h.logger.Debug("session refreshed successfully")
					}
				} else {
					h.logger.Warn("failed to verify refreshed id token", zap.Error(err))
					return sessionData{}, false
				}
			}
		}
	}

	return sess, true
}

func (h Handler) injectHeaders(r *http.Request, rawIDToken string) {
	// Best effort ID token decode (without full verification since it's already verified)
	// Just to extract claims for headers.
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	idToken, err := h.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return
	}

	var claims map[string]interface{}
	if err := idToken.Claims(&claims); err != nil {
		return
	}

	if sub, ok := claims["sub"].(string); ok {
		r.Header.Set(h.HeaderPrefix+"Subject", sub)
	}
	if email, ok := claims["email"].(string); ok {
		r.Header.Set(h.HeaderPrefix+"Email", email)
	}
	if name, ok := claims["name"].(string); ok {
		r.Header.Set(h.HeaderPrefix+"Name", name)
	} else if prefName, ok := claims["preferred_username"].(string); ok {
		r.Header.Set(h.HeaderPrefix+"Name", prefName)
	}
	r.Header.Set(h.HeaderPrefix+"Issuer", idToken.Issuer)
}
