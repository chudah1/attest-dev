package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCORSMiddleware_AllowsConfiguredOrigins(t *testing.T) {
	t.Setenv("CORS_ORIGIN", "https://www.attestdev.com")
	t.Setenv("CORS_ORIGINS", "https://app.attestdev.com, https://staging.attestdev.com")

	handler := corsMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	testCases := []struct {
		name           string
		origin         string
		expectedOrigin string
	}{
		{name: "single origin env", origin: "https://www.attestdev.com", expectedOrigin: "https://www.attestdev.com"},
		{name: "allowlist origin", origin: "https://app.attestdev.com", expectedOrigin: "https://app.attestdev.com"},
		{name: "localhost stays allowed", origin: "http://localhost:5173", expectedOrigin: "http://localhost:5173"},
		{name: "unknown origin blocked", origin: "https://evil.example", expectedOrigin: ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/v1/org", nil)
			req.Header.Set("Origin", tc.origin)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)

			if got := rec.Header().Get("Access-Control-Allow-Origin"); got != tc.expectedOrigin {
				t.Fatalf("Access-Control-Allow-Origin = %q, want %q", got, tc.expectedOrigin)
			}
		})
	}
}

func TestAllowedCORSOrigins_EmptyEnv(t *testing.T) {
	t.Setenv("CORS_ORIGIN", "")
	t.Setenv("CORS_ORIGINS", "")

	allowed := allowedCORSOrigins()
	if len(allowed) != 0 {
		t.Fatalf("expected no configured origins, got %d", len(allowed))
	}
}
