package images

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/watchtower/pkg/types"
)

type stubImageStore struct {
	usage    types.ImageDiskUsage
	report   types.ImagePruneReport
	err      error
	pruned   []bool
	duringFn func()
}

func (s *stubImageStore) GetImageDiskUsage(context.Context) (types.ImageDiskUsage, error) {
	return s.usage, s.err
}

func (s *stubImageStore) PruneImages(_ context.Context, all bool) (types.ImagePruneReport, error) {
	s.pruned = append(s.pruned, all)

	if s.duringFn != nil {
		s.duringFn()
	}

	return s.report, s.err
}

func pruneApp(h *PruneHandler) *fiber.App {
	app := fiber.New(fiber.Config{})
	app.Get(h.UsagePath, h.Usage)
	app.Post(h.PrunePath, h.Prune)

	return app
}

func send(t *testing.T, app *fiber.App, method, target string) (int, map[string]any) {
	t.Helper()

	req := httptest.NewRequestWithContext(t.Context(), method, target, nil)
	resp, err := app.Test(req)
	require.NoError(t, err)

	defer resp.Body.Close()

	var body map[string]any

	if resp.StatusCode == http.StatusOK {
		require.NoError(t, json.NewDecoder(resp.Body).Decode(&body))
	}

	return resp.StatusCode, body
}

func TestPruneHandlerUsage(t *testing.T) {
	t.Parallel()

	store := &stubImageStore{usage: types.ImageDiskUsage{TotalSize: 900, Reclaimable: 300, TotalCount: 5, ActiveCount: 3}}
	status, body := send(t, pruneApp(NewPruneHandler(testLogger(), store, nil)), http.MethodGet, "/v1/images/usage")

	assert.Equal(t, http.StatusOK, status)
	assert.InDelta(t, 900, body["total_size"], 0)
	assert.InDelta(t, 300, body["reclaimable"], 0)
	assert.InDelta(t, 5, body["total_count"], 0)
	assert.InDelta(t, 3, body["active_count"], 0)

	store.err = errors.New("daemon down")
	status, _ = send(t, pruneApp(NewPruneHandler(testLogger(), store, nil)), http.MethodGet, "/v1/images/usage")
	assert.Equal(t, http.StatusInternalServerError, status)
}

func TestPruneHandlerPrune(t *testing.T) {
	t.Parallel()

	store := &stubImageStore{report: types.ImagePruneReport{
		ImagesDeleted:  2,
		Untagged:       []string{"nginx:1.27"},
		SpaceReclaimed: 4096,
	}}

	lock := make(chan bool, 1)
	lock <- true

	store.duringFn = func() {
		assert.Empty(t, lock, "the update lock is held while pruning")
	}

	app := pruneApp(NewPruneHandler(testLogger(), store, lock))

	status, body := send(t, app, http.MethodPost, "/v1/images/prune?all=true")
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, true, body["all"])
	assert.InDelta(t, 2, body["images_deleted"], 0)
	assert.InDelta(t, 4096, body["space_reclaimed"], 0)
	assert.Equal(t, []any{"nginx:1.27"}, body["untagged"])
	assert.Len(t, lock, 1, "the update lock is released afterwards")

	status, body = send(t, app, http.MethodPost, "/v1/images/prune")
	require.Equal(t, http.StatusOK, status)
	assert.Equal(t, false, body["all"], "only dangling images by default")
	assert.Equal(t, []bool{true, false}, store.pruned)

	status, _ = send(t, app, http.MethodPost, "/v1/images/prune?all=maybe")
	assert.Equal(t, http.StatusBadRequest, status)

	store.err = errors.New("daemon down")
	status, _ = send(t, app, http.MethodPost, "/v1/images/prune")
	assert.Equal(t, http.StatusInternalServerError, status)
	assert.Len(t, lock, 1, "the update lock is released after a failure")
}

func TestPruneHandlerRefusesDuringUpdate(t *testing.T) {
	t.Parallel()

	store := &stubImageStore{}
	// An empty lock means an update scan holds it.
	lock := make(chan bool, 1)

	status, _ := send(t, pruneApp(NewPruneHandler(testLogger(), store, lock)), http.MethodPost, "/v1/images/prune?all=true")
	assert.Equal(t, http.StatusConflict, status)
	assert.Empty(t, store.pruned)
}
