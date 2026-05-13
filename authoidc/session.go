package authoidc

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/securecookie"
	"golang.org/x/crypto/hkdf"
)

const flowCookieSuffix = "_flow"

var (
	ErrCookieNotFound = errors.New("auth_oidc: cookie not found")
	ErrCookieExpired  = errors.New("auth_oidc: cookie expired")
	ErrCookieInvalid  = errors.New("auth_oidc: cookie invalid")
)

type flowState struct {
	State        string
	Nonce        string
	PKCEVerifier string
	ReturnTo     string
}

type sessionData struct {
	IDToken      string
	RefreshToken string
	ExpiresAt    time.Time
}

func (h Handler) flowStateCookieName() string {
	return h.CookieName + flowCookieSuffix
}

func (h *Handler) initCookieCodecs() error {
	hashKey, blockKey, err := deriveCookieKeys(h.ClientSecret, h.ClientID, h.Provider)
	if err != nil {
		return err
	}

	flowCodec := securecookie.New(hashKey, blockKey)
	flowCodec.MaxAge(int(time.Duration(h.StateTTL).Seconds()))

	sessionCodec := securecookie.New(hashKey, blockKey)
	sessionCodec.MaxAge(int(time.Duration(h.CookieTTL).Seconds()))

	h.flowCodec = flowCodec
	h.sessionCodec = sessionCodec
	return nil
}

func deriveCookieKeys(clientSecret string, clientID string, provider string) ([]byte, []byte, error) {
	if strings.TrimSpace(clientSecret) == "" {
		return nil, nil, fmt.Errorf("client_secret is required for cookie codecs")
	}

	salt := []byte("caddy-auth-oidc:v1")
	info := []byte(clientID + "\x00" + provider)
	r := hkdf.New(sha256.New, []byte(clientSecret), salt, info)

	buf := make([]byte, 64)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, nil, err
	}
	hashKey := buf[:32]
	blockKey := buf[32:]
	return hashKey, blockKey, nil
}

func (h Handler) cookieSecure(r *http.Request) bool {
	if h.ForceHTTPSCookie != nil && *h.ForceHTTPSCookie {
		return true
	}
	return r.TLS != nil
}

func (h Handler) makeCookie(r *http.Request, name string, value string, ttl time.Duration) *http.Cookie {
	c := &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     h.CookiePath,
		HttpOnly: true,
		Secure:   h.cookieSecure(r),
		SameSite: http.SameSiteLaxMode,
	}
	if h.CookieDomain != "" {
		c.Domain = h.CookieDomain
	}
	if ttl > 0 {
		c.MaxAge = int(ttl.Seconds())
		c.Expires = time.Now().Add(ttl).UTC()
	}
	return c
}

func (h Handler) makeClearCookie(r *http.Request, name string) *http.Cookie {
	c := h.makeCookie(r, name, "", 0)
	c.MaxAge = -1
	c.Expires = time.Unix(0, 0).UTC()
	return c
}

func (h Handler) setFlowStateCookie(w http.ResponseWriter, r *http.Request, state flowState) error {
	if h.flowCodec == nil {
		return errors.New("auth_oidc: flow codec not initialized")
	}
	name := h.flowStateCookieName()
	encoded, err := h.flowCodec.Encode(name, state)
	if err != nil {
		return err
	}
	http.SetCookie(w, h.makeCookie(r, name, encoded, time.Duration(h.StateTTL)))
	return nil
}

func (h Handler) readFlowStateCookie(r *http.Request) (flowState, error) {
	name := h.flowStateCookieName()
	c, err := r.Cookie(name)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return flowState{}, ErrCookieNotFound
		}
		return flowState{}, err
	}

	if h.flowCodec == nil {
		return flowState{}, errors.New("auth_oidc: flow codec not initialized")
	}

	var out flowState
	if err := h.flowCodec.Decode(name, c.Value, &out); err != nil {
		return flowState{}, classifyCookieDecodeErr(err)
	}
	return out, nil
}

func (h Handler) clearFlowStateCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, h.makeClearCookie(r, h.flowStateCookieName()))
}

func (h Handler) setSessionCookie(w http.ResponseWriter, r *http.Request, sess sessionData) error {
	if h.sessionCodec == nil {
		return errors.New("auth_oidc: session codec not initialized")
	}
	name := h.CookieName
	encoded, err := h.sessionCodec.Encode(name, sess)
	if err != nil {
		return err
	}
	http.SetCookie(w, h.makeCookie(r, name, encoded, time.Duration(h.CookieTTL)))
	return nil
}

func (h Handler) readSessionCookie(r *http.Request) (sessionData, error) {
	c, err := r.Cookie(h.CookieName)
	if err != nil {
		if errors.Is(err, http.ErrNoCookie) {
			return sessionData{}, ErrCookieNotFound
		}
		return sessionData{}, err
	}

	if h.sessionCodec == nil {
		return sessionData{}, errors.New("auth_oidc: session codec not initialized")
	}

	var out sessionData
	if err := h.sessionCodec.Decode(h.CookieName, c.Value, &out); err != nil {
		return sessionData{}, classifyCookieDecodeErr(err)
	}
	if !out.ExpiresAt.IsZero() && time.Now().After(out.ExpiresAt) {
		return sessionData{}, ErrCookieExpired
	}
	return out, nil
}

func (h Handler) clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, h.makeClearCookie(r, h.CookieName))
}

func classifyCookieDecodeErr(err error) error {
	var se securecookie.Error
	if errors.As(err, &se) {
		if strings.Contains(strings.ToLower(se.Error()), "expired") {
			return ErrCookieExpired
		}
		return fmt.Errorf("%w: %s", ErrCookieInvalid, se.Error())
	}
	return fmt.Errorf("%w: %v", ErrCookieInvalid, err)
}
