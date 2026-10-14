package settings

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNotificationServices(t *testing.T) {
	dir := t.TempDir()
	store := Open(nil, dir, Values{}, Validators{})

	var applied []string

	require.NoError(t, store.OnNotificationChange(func(urls []string) error {
		if slices.Contains(urls, "bad://") {
			return errors.New("unsupported service")
		}

		applied = urls

		return nil
	}))

	added, err := store.AddNotificationService(" Phone ", " ntfy://ntfy.sh/topic ")
	require.NoError(t, err)
	assert.Equal(t, NotificationService{Name: "Phone", URL: "ntfy://ntfy.sh/topic"}, added)
	assert.Equal(t, []string{"ntfy://ntfy.sh/topic"}, applied)

	_, err = store.AddNotificationService("", "ntfy://ntfy.sh/topic")
	require.ErrorIs(t, err, ErrNotificationExists)

	_, err = store.AddNotificationService("", "bad://")
	require.ErrorIs(t, err, ErrInvalidValue)
	assert.Len(t, store.NotificationServices(), 1, "a rejected service is not saved")

	_, err = store.AddNotificationService("", "  ")
	require.ErrorIs(t, err, ErrInvalidValue)

	// Saved services are applied again when Watchtower restarts.
	reopened := Open(nil, dir, Values{}, Validators{})

	var restored []string

	require.NoError(t, reopened.OnNotificationChange(func(urls []string) error {
		restored = urls

		return nil
	}))
	assert.Equal(t, []string{"ntfy://ntfy.sh/topic"}, restored)

	require.ErrorIs(t, reopened.RemoveNotificationService("unknown"), ErrNotificationNotFound)
	require.NoError(t, reopened.RemoveNotificationService(added.ID()))
	assert.Empty(t, restored)
	assert.Empty(t, reopened.NotificationServices())
}

func TestNotificationServicesSurviveSettingsChanges(t *testing.T) {
	store := Open(nil, t.TempDir(), Values{}, Validators{})

	_, err := store.AddNotificationService("", "ntfy://ntfy.sh/topic")
	require.NoError(t, err)

	require.NoError(t, store.Update(map[string]json.RawMessage{KeyCleanup: json.RawMessage("true")}))
	assert.Len(t, store.NotificationServices(), 1)
}

func TestNotificationSummary(t *testing.T) {
	for _, tt := range []struct {
		url, service, host string
	}{
		{"ntfy://ntfy.sh/secret-topic", "ntfy", "ntfy.sh"},
		{"discord://token@123456789", "discord", ""},
		{"gotify://gotify.example.com/AzyoeNS.D4iJLVa", "gotify", "gotify.example.com"},
		{"smtp://user:pass@mail.example.com:587/?fromaddress=a@b.c", "smtp", "mail.example.com"},
		{"::not a url", "unknown", ""},
	} {
		service, host := NotificationSummary(tt.url)
		assert.Equal(t, tt.service, service, tt.url)
		assert.Equal(t, tt.host, host, tt.url)
	}

	assert.Len(t, NotificationID("ntfy://ntfy.sh/a"), notificationIDLength)
	assert.NotEqual(t, NotificationID("ntfy://ntfy.sh/a"), NotificationID("ntfy://ntfy.sh/b"))
}
