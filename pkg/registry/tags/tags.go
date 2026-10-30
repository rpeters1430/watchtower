package tags

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/distribution/reference"
	"github.com/rs/zerolog"

	registryConfig "github.com/nicholas-fedor/watchtower/internal/config/registry"
	"github.com/nicholas-fedor/watchtower/internal/meta"
	"github.com/nicholas-fedor/watchtower/pkg/registry/auth"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

// cacheTTL defines how long fetched tag lists are cached.
const defaultCacheTTL = 15 * time.Minute

// maxTagsResponseSize limits the response body size for tags list (2 MiB).
const maxTagsResponseSize = 2 << 20

type cachedTagList struct {
	tags      []string
	fetchedAt time.Time
}

var (
	tagsCache   sync.Map
	tagsCacheMu sync.Mutex
)

// TagListResponse represents the OCI/Docker distribution spec tags list JSON payload.
type TagListResponse struct {
	Name string   `json:"name"`
	Tags []string `json:"tags"`
}

// FetchTags fetches all available tags for a container's image repository from its registry.
// Results are cached in memory for defaultCacheTTL to avoid hitting rate limits.
func FetchTags(
	ctx context.Context,
	log *zerolog.Logger,
	container types.Container,
	registryAuth string,
	client auth.Client,
	settings registryConfig.Registry,
	endpoints ...string,
) ([]string, error) {
	imageName := container.ImageName()
	normalizedRef, err := reference.ParseNormalizedNamed(imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to parse image reference %s: %w", imageName, err)
	}

	repoPath := reference.Path(normalizedRef)
	registryHost, err := auth.GetRegistryAddress(log, imageName)
	if err != nil {
		return nil, fmt.Errorf("failed to get registry address for %s: %w", imageName, err)
	}

	cacheKey := fmt.Sprintf("%s/%s", registryHost, repoPath)
	if cachedVal, ok := tagsCache.Load(cacheKey); ok {
		if entry, ok := cachedVal.(cachedTagList); ok {
			if time.Since(entry.fetchedAt) < defaultCacheTTL {
				return entry.tags, nil
			}
		}
	}

	endpoint := ""
	if len(endpoints) > 0 {
		endpoint = endpoints[0]
	}

	scheme := auth.Scheme(settings)
	if endpoint != "" {
		endpointHost, endpointScheme, err := auth.ResolveEndpoint(endpoint, registryHost, scheme)
		if err == nil {
			registryHost = endpointHost
			scheme = endpointScheme
		}
	}

	tagsURL := fmt.Sprintf("%s://%s/v2/%s/tags/list", scheme, registryHost, repoPath)

	tokenResult, authErr := auth.GetToken(log, ctx, container, registryAuth, client, settings, endpoint)
	if authErr != nil {
		log.Debug().
			Err(authErr).
			Str("image", imageName).
			Str("registry", registryHost).
			Msg("Failed to obtain registry token for tags list; proceeding without token")
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, tagsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create tags list request: %w", err)
	}

	if tokenResult.Token != "" {
		req.Header.Set("Authorization", tokenResult.Token)
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", meta.UserAgent)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to execute tags list request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		if authErr != nil {
			return nil, fmt.Errorf("registry returned status %s for tags list (auth error: %w)", resp.Status, authErr)
		}
		return nil, fmt.Errorf("registry returned status %s for tags list", resp.Status)
	}

	lr := io.LimitReader(resp.Body, maxTagsResponseSize)
	bodyBytes, err := io.ReadAll(lr)
	if err != nil {
		return nil, fmt.Errorf("failed to read tags list response: %w", err)
	}

	var tagResp TagListResponse
	err = json.Unmarshal(bodyBytes, &tagResp)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tags list JSON: %w", err)
	}

	tagsCache.Store(cacheKey, cachedTagList{
		tags:      tagResp.Tags,
		fetchedAt: time.Now(),
	})

	return tagResp.Tags, nil
}

// ClearCache clears the in-memory tags list cache (useful in tests).
func ClearCache() {
	tagsCacheMu.Lock()
	defer tagsCacheMu.Unlock()
	tagsCache.Range(func(key, _ any) bool {
		tagsCache.Delete(key)
		return true
	})
}
