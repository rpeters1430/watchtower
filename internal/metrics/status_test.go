package metrics

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/nicholas-fedor/watchtower/pkg/session"
	"github.com/nicholas-fedor/watchtower/pkg/types"
	mockTypes "github.com/nicholas-fedor/watchtower/pkg/types/mocks"
)

func statusReport(t *testing.T, name, state, latestVersion string) *mockTypes.MockContainerReport {
	t.Helper()

	item := mockTypes.NewMockContainerReport(t)
	item.EXPECT().Name().Return("/" + name).Maybe()
	item.EXPECT().ImageName().Return(name + ":latest").Maybe()
	item.EXPECT().CurrentImageID().Return(types.ImageID("sha256:old")).Maybe()
	item.EXPECT().LatestImageID().Return(types.ImageID("sha256:new")).Maybe()
	item.EXPECT().CurrentImageVersion().Return("1.0").Maybe()
	item.EXPECT().LatestImageVersion().Return(latestVersion).Maybe()
	item.EXPECT().Changelog().Return("").Maybe()
	item.EXPECT().Source().Return("").Maybe()
	item.EXPECT().GitRepo().Return("").Maybe()
	item.EXPECT().GitRef().Return("").Maybe()
	item.EXPECT().Error().Return("pull failed").Maybe()
	item.EXPECT().State().Return(state)

	return item
}

func TestNewScanStatuses(t *testing.T) {
	report := mockTypes.NewMockReport(t)
	report.EXPECT().All().Return([]types.ContainerReport{
		statusReport(t, "fresh", session.FreshStateString, ""),
		statusReport(t, "stale", session.StaleStateString, "2.0"),
		statusReport(t, "updated", session.UpdatedStateString, "2.0"),
		statusReport(t, "failed", session.FailedStateString, ""),
		statusReport(t, "skipped", session.SkippedStateString, ""),
	})

	now := time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)
	got := map[string]ContainerStatus{}

	for _, status := range newScanStatuses(report, now) {
		got[status.Name] = status
	}

	if len(got) != 4 {
		t.Fatalf("newScanStatuses() = %+v, want 4 statuses without the skipped container", got)
	}

	if got["fresh"].UpdateAvailable || got["fresh"].CheckedBy != StatusSourceScan || !got["fresh"].Timestamp.Equal(now) {
		t.Errorf("fresh status = %+v, want up to date from a scan", got["fresh"])
	}

	if stale := got["stale"]; !stale.UpdateAvailable || stale.LatestImageVersion != "2.0" || stale.LatestImageID != "sha256:new" {
		t.Errorf("stale status = %+v, want an update to 2.0 waiting", stale)
	}

	if updated := got["updated"]; updated.UpdateAvailable || updated.ImageID != "sha256:new" || updated.CurrentImageVersion != "2.0" {
		t.Errorf("updated status = %+v, want running the new image", updated)
	}

	if failed := got["failed"]; !failed.UpdateAvailable || failed.Error != "pull failed" {
		t.Errorf("failed status = %+v, want the update still waiting with its error", failed)
	}
}

func TestMetrics_RecordStatuses(t *testing.T) {
	path := filepath.Join(t.TempDir(), "checks.json")
	now := time.Now().UTC()

	first := &Metrics{}
	first.PersistStatuses(nil, path)
	first.RecordStatuses([]ContainerStatus{
		{Name: "web", UpdateAvailable: true, Timestamp: now.Add(-time.Hour), CheckedBy: StatusSourceCheck},
		{Name: "db", Timestamp: now.Add(-time.Hour), CheckedBy: StatusSourceCheck},
		{Name: "gone", Timestamp: now.Add(-statusRetention - time.Hour), CheckedBy: StatusSourceCheck},
	})
	// A later partial scan replaces only the containers it looked at.
	first.RecordStatuses([]ContainerStatus{{Name: "web", Timestamp: now, CheckedBy: StatusSourceScan}})

	second := &Metrics{}
	second.PersistStatuses(nil, path)

	got := second.GetStatuses()
	if len(got) != 2 {
		t.Fatalf("GetStatuses() = %+v, want db and web, with the stale entry pruned", got)
	}

	if got[0].Name != "db" || got[1].Name != "web" {
		t.Errorf("GetStatuses() names = %q, %q, want sorted db, web", got[0].Name, got[1].Name)
	}

	if got[1].UpdateAvailable || got[1].CheckedBy != StatusSourceScan {
		t.Errorf("web status = %+v, want the newer scan result", got[1])
	}
}

func TestMetrics_GetStatusesEmpty(t *testing.T) {
	if got := (&Metrics{}).GetStatuses(); got == nil || len(got) != 0 {
		t.Errorf("GetStatuses() = %#v, want an empty, non-nil slice", got)
	}
}
