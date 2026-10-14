package settings

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	runtime "github.com/nicholas-fedor/watchtower/internal/settings"
	mockTypes "github.com/nicholas-fedor/watchtower/pkg/types/mocks"
)

func newNotificationsApp(t *testing.T, configured []string) (*fiber.App, *runtime.Store) {
	t.Helper()

	store := runtime.Open(nil, t.TempDir(), runtime.Values{}, runtime.Validators{})

	notifier := mockTypes.NewMockNotifier(t)
	notifier.EXPECT().GetURLs().RunAndReturn(func() []string {
		urls := append([]string(nil), configured...)
		for _, service := range store.NotificationServices() {
			urls = append(urls, service.URL)
		}

		return urls
	}).Maybe()

	handler := NewNotifications(nil, store, notifier)

	app := fiber.New()
	app.Get(handler.Path, handler.List)
	app.Post(handler.Path, handler.Add)
	app.Delete(handler.Path+"/:id", handler.Remove)

	return app, store
}

func call(t *testing.T, app *fiber.App, method, path, body string) (int, NotificationsResponse, string) {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, path, strings.NewReader(body))
	req.Header.Set(fiber.HeaderContentType, fiber.MIMEApplicationJSON)

	resp, err := app.Test(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	var parsed NotificationsResponse

	_ = json.Unmarshal(data, &parsed)

	return resp.StatusCode, parsed, string(data)
}

func TestNotificationsLifecycle(t *testing.T) {
	t.Parallel()

	app, _ := newNotificationsApp(t, []string{"discord://token@123456789"})

	status, list, _ := call(t, app, http.MethodGet, "/v1/settings/notifications", "")
	require.Equal(t, http.StatusOK, status)
	require.Len(t, list.Services, 1)
	assert.Equal(t, NotificationService{
		ID:      runtime.NotificationID("discord://token@123456789"),
		Service: "discord",
		Source:  SourceConfig,
	}, list.Services[0])
	assert.True(t, list.Saved)

	status, list, raw := call(t, app, http.MethodPost, "/v1/settings/notifications",
		`{"name":"Phone","url":"ntfy://ntfy.sh/secret-topic?token=tk_abc"}`)
	require.Equal(t, http.StatusCreated, status, raw)
	require.Len(t, list.Services, 2)
	assert.Equal(t, "Phone", list.Services[1].Name)
	assert.Equal(t, "ntfy.sh", list.Services[1].Host)
	assert.Equal(t, SourceSettings, list.Services[1].Source)
	assert.NotContains(t, raw, "secret-topic", "responses never include the URL")
	assert.NotContains(t, raw, "tk_abc")

	status, _, _ = call(t, app, http.MethodPost, "/v1/settings/notifications", `{"url":"discord://token@123456789"}`)
	assert.Equal(t, http.StatusConflict, status, "a configured URL cannot be added twice")

	status, _, _ = call(t, app, http.MethodPost, "/v1/settings/notifications", `{"url":""}`)
	assert.Equal(t, http.StatusBadRequest, status)

	status, _, _ = call(t, app, http.MethodPost, "/v1/settings/notifications", `not json`)
	assert.Equal(t, http.StatusBadRequest, status)

	status, _, _ = call(t, app, http.MethodDelete, "/v1/settings/notifications/"+list.Services[0].ID, "")
	assert.Equal(t, http.StatusNotFound, status, "configured services cannot be removed")

	status, list, _ = call(t, app, http.MethodDelete, "/v1/settings/notifications/"+list.Services[1].ID, "")
	require.Equal(t, http.StatusOK, status)
	assert.Len(t, list.Services, 1)
}

func TestNotificationsRejectedURL(t *testing.T) {
	t.Parallel()

	app, store := newNotificationsApp(t, nil)
	require.NoError(t, store.OnNotificationChange(func(urls []string) error {
		if len(urls) > 0 {
			return assert.AnError
		}

		return nil
	}))

	status, _, raw := call(t, app, http.MethodPost, "/v1/settings/notifications", `{"url":"nosuch://x"}`)
	assert.Equal(t, http.StatusBadRequest, status, raw)
	assert.Empty(t, store.NotificationServices())
}
