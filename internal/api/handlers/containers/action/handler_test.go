package action

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockExecutor struct {
	executeFunc func(ctx context.Context, containerName, action, newImageOrTag string) error
}

func (m *mockExecutor) Execute(ctx context.Context, containerName, action, newImageOrTag string) error {
	if m.executeFunc != nil {
		return m.executeFunc(ctx, containerName, action, newImageOrTag)
	}

	return nil
}

func testLogger() *zerolog.Logger {
	logger := zerolog.Nop()

	return &logger
}

func TestResolveNewImage(t *testing.T) {
	tests := []struct {
		name         string
		currentImage string
		input        string
		expected     string
		expectErr    bool
	}{
		{
			name:         "empty input returns error",
			currentImage: "nginx:latest",
			input:        "",
			expectErr:    true,
		},
		{
			name:         "only whitespace returns error",
			currentImage: "nginx:latest",
			input:        "   ",
			expectErr:    true,
		},
		{
			name:         "tag only replaces tag on library image",
			currentImage: "nginx:latest",
			input:        "alpine",
			expected:     "docker.io/library/nginx:alpine",
			expectErr:    false,
		},
		{
			name:         "tag only replaces tag on org repo",
			currentImage: "linuxserver/plex:1.40.0",
			input:        "1.40.1",
			expected:     "docker.io/linuxserver/plex:1.40.1",
			expectErr:    false,
		},
		{
			name:         "tag only on fully qualified image",
			currentImage: "ghcr.io/owner/repo:v1.0.0",
			input:        "v1.1.0",
			expected:     "ghcr.io/owner/repo:v1.1.0",
			expectErr:    false,
		},
		{
			name:         "full image reference specified",
			currentImage: "nginx:latest",
			input:        "redis:7-alpine",
			expected:     "docker.io/library/redis:7-alpine",
			expectErr:    false,
		},
		{
			name:         "full image with org specified without tag defaults to latest",
			currentImage: "nginx:latest",
			input:        "linuxserver/plex",
			expected:     "docker.io/linuxserver/plex:latest",
			expectErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ResolveNewImage(tt.currentImage, tt.input)
			if tt.expectErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expected, result)
			}
		})
	}
}

func TestHandler_Handle(t *testing.T) {
	tests := []struct {
		name           string
		containerName  string
		body           any
		execErr        error
		expectedStatus int
		expectInBody   string
	}{
		{
			name:           "successful start",
			containerName:  "my-app",
			body:           Request{Action: "start"},
			expectedStatus: http.StatusOK,
			expectInBody:   "success",
		},
		{
			name:           "successful stop",
			containerName:  "my-app",
			body:           Request{Action: "stop"},
			expectedStatus: http.StatusOK,
			expectInBody:   "success",
		},
		{
			name:           "successful restart",
			containerName:  "my-app",
			body:           Request{Action: "restart"},
			expectedStatus: http.StatusOK,
			expectInBody:   "success",
		},
		{
			name:           "successful set_tag",
			containerName:  "my-app",
			body:           Request{Action: "set_tag", Tag: "v2.0.0"},
			expectedStatus: http.StatusOK,
			expectInBody:   "success",
		},
		{
			name:           "missing tag on set_tag returns 400",
			containerName:  "my-app",
			body:           Request{Action: "set_tag"},
			expectedStatus: http.StatusBadRequest,
			expectInBody:   "tag or image is required",
		},
		{
			name:           "missing action returns 400",
			containerName:  "my-app",
			body:           Request{},
			expectedStatus: http.StatusBadRequest,
			expectInBody:   "action is required",
		},
		{
			name:           "invalid json returns 400",
			containerName:  "my-app",
			body:           "not-json",
			expectedStatus: http.StatusBadRequest,
			expectInBody:   "invalid request body",
		},
		{
			name:           "container not found returns 404",
			containerName:  "ghost",
			body:           Request{Action: "start"},
			execErr:        ErrContainerNotFound,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "watchtower container returns 400",
			containerName:  "watchtower",
			body:           Request{Action: "restart"},
			execErr:        ErrWatchtowerContainer,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "internal error returns 500",
			containerName:  "my-app",
			body:           Request{Action: "start"},
			execErr:        errors.New("docker daemon down"),
			expectedStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app := fiber.New()
			mockExec := &mockExecutor{
				executeFunc: func(_ context.Context, name, action, newImageOrTag string) error {
					return tt.execErr
				},
			}

			h := New(testLogger(), mockExec)
			app.Post("/v1/containers/:name/action", h.Handle)

			var bodyReader io.Reader
			if str, ok := tt.body.(string); ok {
				bodyReader = bytes.NewBufferString(str)
			} else {
				payload, _ := json.Marshal(tt.body)
				bodyReader = bytes.NewReader(payload)
			}

			req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, "/v1/containers/"+tt.containerName+"/action", bodyReader)
			req.Header.Set("Content-Type", "application/json")

			resp, err := app.Test(req)
			require.NoError(t, err)

			defer resp.Body.Close()

			assert.Equal(t, tt.expectedStatus, resp.StatusCode)

			bodyBytes, _ := io.ReadAll(resp.Body)
			if tt.expectInBody != "" {
				assert.Contains(t, string(bodyBytes), tt.expectInBody)
			}
		})
	}
}

func TestNewExecutor_Defaults(t *testing.T) {
	exec := NewExecutor(nil, nil, 0)
	require.NotNil(t, exec)
	concrete, ok := exec.(*containerExecutor)
	require.True(t, ok)
	assert.Equal(t, 30*time.Second, concrete.timeout)
}
