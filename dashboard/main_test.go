package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReleaseNotesRequiresBasicAuthAndReturnsBuildMetadata(t *testing.T) {
	reader := func(name string) ([]byte, error) {
		if name != "build-info.json" { t.Fatalf("unexpected asset %q", name) }
		return []byte(`{"version":"1.2.3","revision":"abcdef0123456789","notes":"## Fixes\n- Faster checks"}`), nil
	}
	handler := releaseNotesHandler(basicAuthenticator("admin", "secret"), reader)
	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/release-notes", nil))
	if unauthorized.Code != http.StatusUnauthorized || unauthorized.Header().Get("WWW-Authenticate") == "" { t.Fatalf("expected Basic auth challenge, got %d", unauthorized.Code) }

	request := httptest.NewRequest(http.MethodGet, "/api/release-notes", nil)
	request.SetBasicAuth("admin", "secret")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK { t.Fatalf("expected 200, got %d: %s", response.Code, response.Body.String()) }
	if response.Header().Get("Cache-Control") != "no-store" { t.Fatalf("expected no-store, got %q", response.Header().Get("Cache-Control")) }
	var actual buildInfo
	if err := json.Unmarshal(response.Body.Bytes(), &actual); err != nil { t.Fatal(err) }
	want := buildInfo{Version: "1.2.3", Revision: "abcdef0123456789", Notes: "## Fixes\n- Faster checks"}
	if actual != want { t.Fatalf("metadata mismatch: got %#v, want %#v", actual, want) }
}

func TestReleaseNotesDefaultsAndMethodHandling(t *testing.T) {
	for name, reader := range map[string]func(string) ([]byte, error){
		"missing": func(string) ([]byte, error) { return nil, errors.New("missing") },
		"invalid": func(string) ([]byte, error) { return []byte("{invalid"), nil },
		"wrong types": func(string) ([]byte, error) { return []byte(`{"version":1,"revision":null,"notes":false}`), nil },
	} {
		t.Run(name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/api/release-notes", nil)
			request.SetBasicAuth("admin", "secret")
			response := httptest.NewRecorder()
			releaseNotesHandler(basicAuthenticator("admin", "secret"), reader).ServeHTTP(response, request)
			if response.Code != http.StatusOK { t.Fatalf("expected 200, got %d", response.Code) }
			if !strings.Contains(response.Body.String(), `"version":""`) || !strings.Contains(response.Body.String(), `"revision":""`) || !strings.Contains(response.Body.String(), `"notes":""`) {
				t.Fatalf("expected empty defaults, got %s", response.Body.String())
			}
		})
	}

	request := httptest.NewRequest(http.MethodPost, "/api/release-notes", nil)
	request.SetBasicAuth("admin", "secret")
	response := httptest.NewRecorder()
	releaseNotesHandler(basicAuthenticator("admin", "secret"), func(string) ([]byte, error) { return []byte(`{}`), nil }).ServeHTTP(response, request)
	if response.Code != http.StatusMethodNotAllowed { t.Fatalf("expected 405, got %d", response.Code) }
}
