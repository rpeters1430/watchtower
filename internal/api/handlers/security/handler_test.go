package security

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/watchtower/internal/security"
	"github.com/nicholas-fedor/watchtower/pkg/scanner"
)

var errList = errors.New("docker is down")

type stubScanner struct {
	release chan struct{}
}

func (s *stubScanner) Name() string { return "trivy" }

func (s *stubScanner) ReviewUpdate(context.Context, string, string) (*scanner.Review, error) {
	return &scanner.Review{}, nil
}

func (s *stubScanner) Expected(string) (time.Duration, bool) { return 0, false }

func (s *stubScanner) Rescan(_ context.Context, image string) (*scanner.Result, error) {
	if s.release != nil {
		<-s.release
	}

	return &scanner.Result{
		Scanner: "trivy",
		Image:   image,
		Findings: []scanner.Finding{{
			ID: "CVE-2026-1", Kind: scanner.KindVulnerability, Severity: scanner.SeverityHigh,
			Package: "openssl", InstalledVersion: "3.0.1", FixedVersion: "3.0.2",
		}},
	}, nil
}

func targets(context.Context) ([]security.Target, error) {
	return []security.Target{
		{Name: "/web", Image: "nginx", ImageID: "sha256:web"},
		{Name: "/db", Image: "postgres", ImageID: "sha256:db"},
	}, nil
}

func newApp(t *testing.T, service *security.Service, list func(context.Context) ([]security.Target, error)) *fiber.App {
	t.Helper()

	handler := New(nil, t.Context(), service, list)

	app := fiber.New()
	app.Get(handler.Path, handler.Get)
	app.Post(handler.Path+"/scan", handler.Scan)
	app.Get(handler.Path+"/:name", handler.Report)

	return app
}

func newService(stub *stubScanner) *security.Service {
	return security.NewService(nil, stub, security.OpenStore(nil, ""), security.Options{
		ScannerImage: func() string { return "aquasec/trivy:latest" },
		Enabled:      func() bool { return true },
		Gate:         func() scanner.Gate { return scanner.GateHigh },
	})
}

func send(t *testing.T, app *fiber.App, method, path, body string) (int, string) {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

	resp, err := app.Test(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	return resp.StatusCode, string(data)
}

func overview(t *testing.T, app *fiber.App) Response {
	t.Helper()

	status, body := send(t, app, http.MethodGet, Path, "")
	require.Equal(t, http.StatusOK, status, body)

	var response Response
	require.NoError(t, json.Unmarshal([]byte(body), &response))

	return response
}

func TestUnavailable(t *testing.T) {
	t.Parallel()

	app := newApp(t, nil, targets)

	response := overview(t, app)
	assert.False(t, response.Available)
	assert.NotEmpty(t, response.Reason)
	assert.Equal(t, scanner.GateOff, response.Gate)
	assert.Empty(t, response.Containers)

	status, _ := send(t, app, http.MethodPost, Path+"/scan", "")
	assert.Equal(t, http.StatusServiceUnavailable, status)

	status, _ = send(t, app, http.MethodGet, Path+"/web", "")
	assert.Equal(t, http.StatusServiceUnavailable, status)
}

func TestScanAndReport(t *testing.T) {
	t.Parallel()

	service := newService(&stubScanner{})
	app := newApp(t, service, targets)

	response := overview(t, app)
	assert.True(t, response.Available)
	assert.Equal(t, "trivy", response.Scanner)
	assert.Equal(t, "aquasec/trivy:latest", response.ScannerImage)
	assert.True(t, response.ScanUpdates)
	assert.Equal(t, scanner.GateHigh, response.Gate)

	status, body := send(t, app, http.MethodGet, Path+"/web", "")
	assert.Equal(t, http.StatusNotFound, status, body)

	status, body = send(t, app, http.MethodPost, Path+"/scan", `{"containers":["web"]}`)
	require.Equal(t, http.StatusAccepted, status, body)
	assert.Contains(t, body, `"total":1`)

	require.Eventually(t, func() bool { return !service.Job().Running }, 5*time.Second, 5*time.Millisecond)

	response = overview(t, app)
	require.Len(t, response.Containers, 1)
	assert.Equal(t, "web", response.Containers[0].Name)
	assert.Equal(t, 1, response.Containers[0].Counts.High)
	assert.Nil(t, response.Containers[0].Findings, "the overview leaves out finding lists")

	status, body = send(t, app, http.MethodGet, Path+"/web", "")
	require.Equal(t, http.StatusOK, status, body)
	assert.Contains(t, body, `"fixed_version":"3.0.2"`)
}

func TestScanErrors(t *testing.T) {
	t.Parallel()

	stub := &stubScanner{release: make(chan struct{})}
	service := newService(stub)
	app := newApp(t, service, targets)

	status, _ := send(t, app, http.MethodPost, Path+"/scan", `not json`)
	assert.Equal(t, http.StatusBadRequest, status)

	status, _ = send(t, app, http.MethodPost, Path+"/scan", `{"containers":["nope"]}`)
	assert.Equal(t, http.StatusNotFound, status)

	// An empty body scans every watched container.
	status, body := send(t, app, http.MethodPost, Path+"/scan", "")
	require.Equal(t, http.StatusAccepted, status)
	assert.Contains(t, body, `"total":2`)

	status, _ = send(t, app, http.MethodPost, Path+"/scan", "")
	assert.Equal(t, http.StatusConflict, status)

	close(stub.release)
	require.Eventually(t, func() bool { return !service.Job().Running }, 5*time.Second, 5*time.Millisecond)

	failing := newApp(t, newService(&stubScanner{}), func(context.Context) ([]security.Target, error) {
		return nil, errList
	})
	status, _ = send(t, failing, http.MethodPost, Path+"/scan", "")
	assert.Equal(t, http.StatusInternalServerError, status)
}
