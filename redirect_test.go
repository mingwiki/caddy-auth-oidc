package caddyauthoidc

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func TestGetAbsoluteRedirectURL(t *testing.T) {
	h := Handler{}

	tests := []struct {
		name       string
		target     string
		reqURL     string
		fwdHost    string
		fwdProto   string
		tls        bool
		want       string
	}{
		{
			name:   "absolute target",
			target: "https://example.com/foo",
			reqURL: "http://localhost",
			want:   "https://example.com/foo",
		},
		{
			name:   "relative target",
			target: "/foo",
			reqURL: "http://localhost:8080/bar",
			want:   "http://localhost:8080/foo",
		},
		{
			name:     "forwarded host and proto",
			target:   "/foo",
			reqURL:   "http://internal:8080/bar",
			fwdHost:  "example.com",
			fwdProto: "https",
			want:     "https://example.com/foo",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", tt.reqURL, nil)
			if tt.fwdHost != "" {
				r.Header.Set("X-Forwarded-Host", tt.fwdHost)
			}
			if tt.fwdProto != "" {
				r.Header.Set("X-Forwarded-Proto", tt.fwdProto)
			}
			if tt.tls {
				r.TLS = &tls.ConnectionState{}
			}

			got := h.getAbsoluteRedirectURL(r, tt.target)
			if got != tt.want {
				t.Errorf("getAbsoluteRedirectURL() = %v, want %v", got, tt.want)
			}
		})
	}
}