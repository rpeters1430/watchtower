package tags

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	registryConfig "github.com/nicholas-fedor/watchtower/internal/config/registry"
	"github.com/nicholas-fedor/watchtower/pkg/types/mocks"
)

type dummyClient struct {
	client *http.Client
}

func (d *dummyClient) Do(req *http.Request) (*http.Response, error) {
	return d.client.Do(req)
}

func TestTagsCache(t *testing.T) {
	ClearCache()
	defer ClearCache()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"name":"test/app","tags":["1.0.0","1.1.0","1.2.0"]}`))
	}))
	defer server.Close()

	logger := zerolog.Nop()
	mockContainer := mocks.NewMockContainer(t)
	mockContainer.EXPECT().ImageName().Return(server.Listener.Addr().String() + "/test/app:1.0.0").Maybe()

	client := &dummyClient{client: server.Client()}
	settings := registryConfig.Registry{
		InsecureRegistries: []string{server.Listener.Addr().String()},
	}

	tags, err := FetchTags(context.Background(), &logger, mockContainer, "", client, settings)
	if err == nil {
		assert.Equal(t, []string{"1.0.0", "1.1.0", "1.2.0"}, tags)
		latest, ok := GetLatestNewerVersion("1.0.0", tags)
		require.True(t, ok)
		assert.Equal(t, "1.2.0", latest)
	}
}
