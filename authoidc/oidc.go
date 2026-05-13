package authoidc

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func (h *Handler) initOIDC(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	// Use the external issuer URL for token validation, but discover via
	// the local backend to avoid the chicken-and-egg problem where Caddy
	// needs to reach its own reverse-proxied endpoint before starting.
	discoveryURL := h.Provider
	issuerURL := h.IssuerURL
	if issuerURL == "" {
		issuerURL = h.Provider
	}
	if discoveryURL != issuerURL {
		ctx = oidc.InsecureIssuerURLContext(ctx, issuerURL)
	}

	provider, err := oidc.NewProvider(ctx, discoveryURL)
	if err != nil {
		return fmt.Errorf("auth_oidc: failed to discover provider: %w", err)
	}
	h.provider = provider

	h.verifier = provider.Verifier(&oidc.Config{
		ClientID: h.ClientID,
	})

	h.oauth2Config = oauth2.Config{
		ClientID:     h.ClientID,
		ClientSecret: h.ClientSecret,
		Endpoint:     provider.Endpoint(),
		Scopes:       h.Scopes,
	}

	return nil
}

func generateRandomString(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func generatePKCE() (verifier, challenge string, err error) {
	v, err := generateRandomString(32)
	if err != nil {
		return "", "", err
	}
	hash := sha256.Sum256([]byte(v))
	c := base64.RawURLEncoding.EncodeToString(hash[:])
	return v, c, nil
}

func (h *Handler) getCallbackURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}

	u := url.URL{
		Scheme: scheme,
		Host:   host,
		Path:   "/auth/callback",
	}
	return u.String()
}
