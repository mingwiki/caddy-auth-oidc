package authoidc

import (
	"context"
	"net/http"
	"net/url"
	"time"

	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func (h Handler) serveLogin(w http.ResponseWriter, r *http.Request) error {
	state, err := generateRandomString(32)
	if err != nil {
		h.logger.Error("failed to generate state", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	nonce, err := generateRandomString(32)
	if err != nil {
		h.logger.Error("failed to generate nonce", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	verifier, challenge, err := generatePKCE()
	if err != nil {
		h.logger.Error("failed to generate pkce", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	returnTo := r.URL.Query().Get("return_to")
	if returnTo == "" {
		returnTo = "/"
	}

	fs := flowState{
		State:        state,
		Nonce:        nonce,
		PKCEVerifier: verifier,
		ReturnTo:     returnTo,
	}

	if err := h.setFlowStateCookie(w, r, fs); err != nil {
		h.logger.Error("failed to set flow state cookie", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	authURL := h.oauth2Config.AuthCodeURL(state,
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
		oauth2.SetAuthURLParam("redirect_uri", h.getCallbackURL(r)),
	)

	http.Redirect(w, r, authURL, http.StatusFound)
	return nil
}

func (h Handler) serveCallback(w http.ResponseWriter, r *http.Request) error {
	fs, err := h.readFlowStateCookie(r)
	if err != nil {
		h.logger.Warn("failed to read flow state cookie", zap.Error(err))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	// Clear flow state cookie
	h.clearFlowStateCookie(w, r)

	if r.URL.Query().Get("state") != fs.State {
		h.logger.Warn("state mismatch")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	code := r.URL.Query().Get("code")
	if code == "" {
		h.logger.Warn("no code in callback")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	oauth2Token, err := h.oauth2Config.Exchange(ctx, code,
		oauth2.SetAuthURLParam("code_verifier", fs.PKCEVerifier),
		oauth2.SetAuthURLParam("redirect_uri", h.getCallbackURL(r)),
	)
	if err != nil {
		h.logger.Error("failed to exchange code", zap.Error(err))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		h.logger.Error("no id_token in token response")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	idToken, err := h.verifier.Verify(ctx, rawIDToken)
	if err != nil {
		h.logger.Error("failed to verify id token", zap.Error(err))
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	if idToken.Nonce != fs.Nonce {
		h.logger.Warn("nonce mismatch")
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return nil
	}

	sess := sessionData{
		IDToken:      rawIDToken,
		RefreshToken: oauth2Token.RefreshToken,
		ExpiresAt:    idToken.Expiry,
	}

	if err := h.setSessionCookie(w, r, sess); err != nil {
		h.logger.Error("failed to set session cookie", zap.Error(err))
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return nil
	}

	http.Redirect(w, r, fs.ReturnTo, http.StatusFound)
	return nil
}

func (h Handler) serveLogout(w http.ResponseWriter, r *http.Request) error {
	h.clearFlowStateCookie(w, r)

	// Read session before clearing to get ID token hint if possible
	var idTokenHint string
	if sess, err := h.readSessionCookie(r); err == nil {
		idTokenHint = sess.IDToken
	}

	h.clearSessionCookie(w, r)

	redirectURL := h.LogoutRedirect
	if redirectURL == "" {
		redirectURL = "/"
	}

	// Best-effort provider end-session
	if h.provider != nil {
		var claims struct {
			EndSessionEndpoint string `json:"end_session_endpoint"`
		}
		if err := h.provider.Claims(&claims); err == nil && claims.EndSessionEndpoint != "" {
			u, err := url.Parse(claims.EndSessionEndpoint)
			if err == nil {
				q := u.Query()
				if idTokenHint != "" {
					q.Set("id_token_hint", idTokenHint)
				}

				absRedirect := h.getAbsoluteRedirectURL(r, redirectURL)
				if absRedirect != "" {
					q.Set("post_logout_redirect_uri", absRedirect)
				}

				u.RawQuery = q.Encode()
				redirectURL = u.String()
			}
		}
	}

	http.Redirect(w, r, redirectURL, http.StatusFound)
	return nil
}

func (h Handler) getAbsoluteRedirectURL(r *http.Request, target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	if u.IsAbs() {
		return u.String()
	}

	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	host := r.Host
	if fwdHost := r.Header.Get("X-Forwarded-Host"); fwdHost != "" {
		host = fwdHost
	}

	u.Scheme = scheme
	u.Host = host
	return u.String()
}
