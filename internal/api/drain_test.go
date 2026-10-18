package api_test

import (
	"context"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/watchtower/internal/api"
	"github.com/nicholas-fedor/watchtower/internal/metrics"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

// TestSetupAndStartAPI_StoppedAfterDrain verifies that in background mode the
// returned channel closes only after the server has shut down and finished the
// request it was serving, so a caller can wait for the drain before exiting.
func TestSetupAndStartAPI_StoppedAfterDrain(t *testing.T) {
	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	host, port, err := net.SplitHostPort(addr)
	require.NoError(t, err)

	entered := make(chan struct{})
	release := make(chan struct{})

	// Release the handler even when the test fails early, so it does not stay
	// blocked after the test ends.
	releaseHandler := sync.OnceFunc(func() { close(release) })
	t.Cleanup(releaseHandler)

	opts := fixtureOptions(newFixtureClient(t), newFixtureMetrics(t))
	opts.Host, opts.Port = host, port
	opts.RunUpdatesWithNotifications = func(context.Context, types.Filter, types.UpdateParams) *metrics.Metric {
		close(entered)
		<-release

		return &metrics.Metric{}
	}

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	stopped, err := api.SetupAndStartAPI(ctx, opts)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, "http://"+addr+"/v1/update", nil)
	require.NoError(t, err)
	req.Header.Set(fiber.HeaderAuthorization, "Bearer "+fixtureAPIToken)

	statuses := make(chan int, 1)

	go func() {
		resp, doErr := http.DefaultClient.Do(req)
		if doErr != nil {
			statuses <- 0

			return
		}

		_ = resp.Body.Close()
		statuses <- resp.StatusCode
	}()

	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the update request did not reach the handler")
	}

	cancel()

	// The server keeps draining while the update request is in flight.
	select {
	case <-stopped:
		t.Fatal("the server reported that it stopped before its in-flight request finished")
	case <-time.After(200 * time.Millisecond):
	}

	releaseHandler()

	select {
	case status := <-statuses:
		assert.Equal(t, http.StatusOK, status)
	case <-time.After(5 * time.Second):
		t.Fatal("the update request did not finish after its handler was released")
	}

	select {
	case <-stopped:
	case <-time.After(api.ShutdownGracePeriod + 2*time.Second):
		t.Fatal("the server did not report that it stopped")
	}
}
