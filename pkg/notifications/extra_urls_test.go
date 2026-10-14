package notifications

import (
	"testing"
	"time"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetExtraURLs(t *testing.T) {
	notifier := createNotifier(testLogger(), []string{"logger://"}, zerolog.InfoLevel, "", false, StaticData{}, false, time.Duration(0))
	t.Cleanup(notifier.Close)

	require.NoError(t, notifier.SetExtraURLs([]string{"ntfy://ntfy.sh/watchtower-test"}))
	assert.Equal(t, []string{"logger://", "ntfy://ntfy.sh/watchtower-test"}, notifier.GetURLs())
	assert.Equal(t, []string{"logger", "ntfy"}, notifier.GetNames())

	// Replacing the extra URLs keeps the configured ones.
	require.NoError(t, notifier.SetExtraURLs(nil))
	assert.Equal(t, []string{"logger://"}, notifier.GetURLs())

	// A URL Shoutrrr cannot use changes nothing.
	require.Error(t, notifier.SetExtraURLs([]string{"nosuchservice://example.com"}))
	assert.Equal(t, []string{"logger://"}, notifier.GetURLs())
}
