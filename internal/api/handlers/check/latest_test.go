package check

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/watchtower/internal/metrics"
)

func TestLatestHandler(t *testing.T) {
	older := time.Date(2026, 10, 14, 10, 0, 0, 0, time.UTC)
	newer := older.Add(time.Hour)

	tests := []struct {
		name      string
		statuses  []metrics.ContainerStatus
		wantCount int
		wantAt    *time.Time
	}{
		{name: "before the first check", statuses: nil, wantCount: 0},
		{
			name: "reports the newest timestamp",
			statuses: []metrics.ContainerStatus{
				{Name: "db", Timestamp: newer},
				{Name: "web", UpdateAvailable: true, Timestamp: older},
			},
			wantCount: 2,
			wantAt:    &newer,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewLatest(nil, func() []metrics.ContainerStatus { return tt.statuses })

			app := fiber.New()
			app.Get(handler.Path, handler.Handle)

			req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/v1/check", nil)
			resp, err := app.Test(req)
			require.NoError(t, err)

			defer resp.Body.Close()

			require.Equal(t, http.StatusOK, resp.StatusCode)

			var body LatestResponse
			require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
			assert.Equal(t, tt.wantCount, body.Count)
			assert.Len(t, body.Containers, tt.wantCount)

			if tt.wantAt == nil {
				assert.Nil(t, body.CheckedAt)
			} else {
				require.NotNil(t, body.CheckedAt)
				assert.True(t, tt.wantAt.Equal(*body.CheckedAt))
			}
		})
	}
}
