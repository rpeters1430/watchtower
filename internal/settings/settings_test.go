package settings

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/watchtower/pkg/scanner"
	"github.com/nicholas-fedor/watchtower/pkg/types"
)

var (
	errBadSchedule = errors.New("bad schedule")
	errLinked      = errors.New("containers are linked")
)

func changes(t *testing.T, body string) map[string]json.RawMessage {
	t.Helper()

	var parsed map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(body), &parsed))

	return parsed
}

func rejectBadSchedule(spec string) error {
	if spec == "never" {
		return errBadSchedule
	}

	return nil
}

func TestOpenWithoutDataDir(t *testing.T) {
	t.Parallel()

	defaults := Values{Cleanup: true, Schedule: "@every 24h"}

	for _, dir := range []string{"", filepath.Join(t.TempDir(), "missing")} {
		store := Open(nil, dir, defaults, Validators{})

		assert.False(t, store.Persistent())
		assert.Equal(t, defaults, store.Effective())

		// Changes still apply for the life of the process.
		require.NoError(t, store.Update(changes(t, `{"monitor_only":true}`)))
		assert.True(t, store.Effective().MonitorOnly)
	}
}

func TestUpdateAppliesAndPersists(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	defaults := Values{Cleanup: true, Schedule: "@every 24h"}

	store := Open(nil, dir, defaults, Validators{Schedule: rejectBadSchedule})
	require.True(t, store.Persistent())

	require.NoError(t, store.Update(changes(t, `{"monitor_only":true,"cleanup":false,"schedule":" 0 0 4 * * * "}`)))

	want := Values{MonitorOnly: true, Cleanup: false, Schedule: "0 0 4 * * *"}
	assert.Equal(t, want, store.Effective())
	assert.Equal(t, defaults, store.Defaults())
	assert.Equal(t, map[string]bool{
		KeyMonitorOnly:        true,
		KeyCleanup:            true,
		KeyRollingRestart:     false,
		KeySchedule:           true,
		KeyAutoRollback:       false,
		KeyIncludeStopped:     false,
		KeyContainerOverrides: false,
		KeyScan:               false,
		KeyScanGate:           false,
		KeyScanner:            false,
		KeyScanSecrets:        false,
	}, store.Overridden())
	assert.Equal(t, Snapshot{
		Effective:  want,
		Defaults:   defaults,
		Overridden: store.Overridden(),
		Persistent: true,
	}, store.Snapshot())

	// A new store over the same directory sees the saved overrides.
	reopened := Open(nil, dir, defaults, Validators{Schedule: rejectBadSchedule})
	assert.Equal(t, want, reopened.Effective())
}

func TestUpdateIncludeStopped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := Open(nil, dir, Values{}, Validators{})

	require.NoError(t, store.Update(changes(t, `{"include_stopped":true}`)))
	assert.True(t, store.Effective().IncludeStopped)
	assert.True(t, store.Overridden()[KeyIncludeStopped])
	assert.True(t, Open(nil, dir, Values{}, Validators{}).Effective().IncludeStopped)

	require.ErrorIs(t, store.Update(changes(t, `{"include_stopped":"yes"}`)), ErrInvalidValue)

	require.NoError(t, store.Update(changes(t, `{"include_stopped":null}`)))
	assert.False(t, store.Effective().IncludeStopped)
	assert.False(t, store.Overridden()[KeyIncludeStopped])
}

func TestUpdateDoesNotApplyWhenPersistenceFails(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	defaults := Values{Cleanup: true}
	store := Open(nil, dir, defaults, Validators{})

	require.NoError(t, os.RemoveAll(dir))
	require.NoError(t, os.WriteFile(dir, []byte("block directory creation"), 0o600))

	err := store.Update(changes(t, `{"monitor_only":true}`))

	require.ErrorIs(t, err, ErrPersistence)
	assert.Equal(t, defaults, store.Effective())
	assert.False(t, store.Snapshot().Overridden[KeyMonitorOnly])
}

func TestUpdateContainerOverrides(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	defaults := Values{}

	store := Open(nil, dir, defaults, Validators{})
	require.NoError(t, store.Update(changes(t, `{"auto_rollback":true,"container_overrides":{"plex":"pinned","nextcloud":"monitor_only"}}`)))

	eff := store.Effective()
	assert.True(t, eff.AutoRollback)
	assert.Equal(t, map[string]string{"plex": "pinned", "nextcloud": "monitor_only"}, eff.ContainerOverrides)

	// Setting override to "auto" removes that container override
	require.NoError(t, store.Update(changes(t, `{"container_overrides":{"plex":"auto"}}`)))
	assert.Equal(t, map[string]string{"nextcloud": "monitor_only"}, store.Effective().ContainerOverrides)
}

func TestUpdateNullResetsToDefault(t *testing.T) {
	t.Parallel()

	store := Open(nil, t.TempDir(), Values{Cleanup: true}, Validators{})

	require.NoError(t, store.Update(changes(t, `{"cleanup":false}`)))
	require.False(t, store.Effective().Cleanup)

	require.NoError(t, store.Update(changes(t, `{"cleanup":null}`)))
	assert.True(t, store.Effective().Cleanup)
	assert.False(t, store.Overridden()[KeyCleanup])
}

func TestUpdateRejectsInvalidChanges(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
		want error
	}{
		{name: "unknown setting", body: `{"no_pull":true}`, want: ErrUnknownSetting},
		{name: "wrong type", body: `{"cleanup":"yes"}`, want: ErrInvalidValue},
		{name: "schedule wrong type", body: `{"schedule":5}`, want: ErrInvalidValue},
		{name: "schedule fails validation", body: `{"schedule":"never"}`, want: errBadSchedule},
		{
			name: "rolling restart with monitor only",
			body: `{"monitor_only":true,"rolling_restart":true}`,
			want: ErrIncompatible,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			defaults := Values{Cleanup: true, Schedule: "@every 24h"}
			store := Open(nil, t.TempDir(), defaults, Validators{Schedule: rejectBadSchedule})

			err := store.Update(changes(t, tt.body))

			require.ErrorIs(t, err, tt.want)
			assert.Equal(t, defaults, store.Effective(), "a rejected update must change nothing")
		})
	}
}

func TestUpdateIsAtomic(t *testing.T) {
	t.Parallel()

	defaults := Values{Schedule: "@every 24h"}
	store := Open(nil, t.TempDir(), defaults, Validators{Schedule: rejectBadSchedule})

	err := store.Update(changes(t, `{"cleanup":true,"schedule":"never"}`))

	require.Error(t, err)
	assert.Equal(t, defaults, store.Effective())
}

func TestRollingRestartValidator(t *testing.T) {
	t.Parallel()

	calls := 0
	store := Open(nil, "", Values{}, Validators{RollingRestart: func() error {
		calls++

		return errLinked
	}})

	require.ErrorIs(t, store.Update(changes(t, `{"rolling_restart":true}`)), errLinked)
	assert.False(t, store.Effective().RollingRestart)

	// Unrelated changes do not consult the validator.
	require.NoError(t, store.Update(changes(t, `{"cleanup":true}`)))
	assert.Equal(t, 1, calls)
}

// A validator can read the store it validates for. The rolling restart
// validator lists containers, and the Docker client reads include_stopped
// from the store while it does.
func TestValidatorCanReadStore(t *testing.T) {
	t.Parallel()

	var store *Store

	store = Open(nil, "", Values{}, Validators{RollingRestart: func() error {
		_ = store.Effective()

		return nil
	}})

	change := changes(t, `{"rolling_restart":true}`)
	done := make(chan error, 1)

	go func() { done <- store.Update(change) }()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Update deadlocked while its validator read the store")
	}

	assert.True(t, store.Effective().RollingRestart)
}

// Readers run while a change is validated, so a change must not edit maps
// they can see.
func TestUpdateContainerOverridesWhileReading(t *testing.T) {
	t.Parallel()

	store := Open(nil, "", Values{}, Validators{})
	require.NoError(t, store.Update(changes(t, `{"container_overrides":{"web":"pinned"}}`)))

	stop := make(chan struct{})
	readerDone := make(chan struct{})

	go func() {
		defer close(readerDone)

		for {
			select {
			case <-stop:
				return
			default:
				_ = store.Effective().ContainerOverrides["web"]
			}
		}
	}()

	for range 100 {
		require.NoError(t, store.Update(changes(t, `{"container_overrides":{"db":"monitor_only"}}`)))
		require.NoError(t, store.Update(changes(t, `{"container_overrides":{"db":"auto"}}`)))
	}

	close(stop)
	<-readerDone

	assert.Equal(t, map[string]string{"web": "pinned"}, store.Effective().ContainerOverrides)
}

func TestLoadKeepsOtherSettingsWhenRollingRestartNoLongerApplies(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		saved     string
		validator func() error
		want      Values
	}{
		{
			name:      "dependencies",
			saved:     `{"rolling_restart":true,"cleanup":true,"scan_secrets":false}`,
			validator: func() error { return errLinked },
			want:      Values{Cleanup: true, ScanSecrets: false},
		},
		{
			name:  "incompatible with monitor only",
			saved: `{"monitor_only":true,"rolling_restart":true}`,
			want:  Values{MonitorOnly: true, ScanSecrets: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, FileName), []byte(tt.saved), 0o600))

			store := Open(nil, dir, Values{ScanSecrets: true}, Validators{RollingRestart: tt.validator})

			assert.Equal(t, tt.want, store.Effective())
			assert.False(t, store.Overridden()[KeyRollingRestart])
		})
	}
}

func TestScheduleChangesDeliversLatest(t *testing.T) {
	t.Parallel()

	store := Open(nil, "", Values{Schedule: "@every 24h"}, Validators{})

	require.NoError(t, store.Update(changes(t, `{"schedule":"@every 6h"}`)))
	require.NoError(t, store.Update(changes(t, `{"schedule":"@every 1h"}`)))
	// A change that leaves the schedule alone announces nothing.
	require.NoError(t, store.Update(changes(t, `{"cleanup":true}`)))

	select {
	case spec := <-store.ScheduleChanges():
		assert.Equal(t, "@every 1h", spec)
	default:
		t.Fatal("expected a schedule change")
	}

	select {
	case spec := <-store.ScheduleChanges():
		t.Fatalf("unexpected second schedule change %q", spec)
	default:
	}
}

func TestLoadDropsSettingsThatNoLongerApply(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		saved string
	}{
		{name: "not JSON", saved: `{`},
		{name: "invalid schedule", saved: `{"schedule":"never"}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			require.NoError(t, os.WriteFile(filepath.Join(dir, FileName), []byte(tt.saved), 0o600))

			defaults := Values{Schedule: "@every 24h"}
			store := Open(nil, dir, defaults, Validators{Schedule: rejectBadSchedule})

			assert.Equal(t, defaults, store.Effective())
		})
	}
}

func TestApplyTo(t *testing.T) {
	t.Parallel()

	store := Open(nil, "", Values{Cleanup: true}, Validators{})
	require.NoError(t, store.Update(changes(t, `{"monitor_only":true}`)))

	params := store.ApplyTo(types.UpdateParams{NoPull: true, RollingRestart: true})

	assert.True(t, params.MonitorOnly)
	assert.True(t, params.Cleanup)
	assert.False(t, params.RollingRestart)
	assert.True(t, params.NoPull, "settings the store does not own are left alone")

	var none *Store

	assert.Equal(t, types.UpdateParams{NoPull: true}, none.ApplyTo(types.UpdateParams{NoPull: true}))
}

type fakeReviewer struct{}

func (fakeReviewer) ReviewUpdate(context.Context, string, string) (*scanner.Review, error) {
	return &scanner.Review{}, nil
}

func TestScanSettings(t *testing.T) {
	t.Parallel()

	store := Open(nil, t.TempDir(), Values{ScanGate: scanner.GateOff}, Validators{})
	params := types.UpdateParams{SecurityReviewer: fakeReviewer{}}

	// Scanning is off by default, so the reviewer is not handed on.
	assert.Nil(t, store.ApplyTo(params).SecurityReviewer)

	require.NoError(t, store.Update(changes(t, `{"scan":true,"scan_gate":"HIGH"}`)))
	assert.Equal(t, scanner.GateHigh, store.Effective().ScanGate)
	assert.NotNil(t, store.ApplyTo(params).SecurityReviewer)
	assert.True(t, store.Overridden()[KeyScanGate])

	err := store.Update(changes(t, `{"scan_gate":"severe"}`))
	require.ErrorIs(t, err, ErrInvalidValue)
	assert.Equal(t, scanner.GateHigh, store.Effective().ScanGate)

	require.NoError(t, store.Update(changes(t, `{"scan_gate":null}`)))
	assert.Equal(t, scanner.GateOff, store.Effective().ScanGate)
	assert.False(t, store.Overridden()[KeyScanGate])
}

func TestScannerSetting(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := Open(nil, dir, Values{Scanner: scanner.TrivyName}, Validators{})

	require.NoError(t, store.Update(changes(t, `{"scanner":"Grype"}`)))
	assert.Equal(t, scanner.GrypeName, store.Effective().Scanner)
	assert.True(t, store.Overridden()[KeyScanner])

	err := store.Update(changes(t, `{"scanner":"clair"}`))
	require.ErrorIs(t, err, ErrInvalidValue)
	assert.Equal(t, scanner.GrypeName, store.Effective().Scanner)

	// The choice survives a restart.
	reopened := Open(nil, dir, Values{Scanner: scanner.TrivyName}, Validators{})
	assert.Equal(t, scanner.GrypeName, reopened.Effective().Scanner)

	require.NoError(t, reopened.Update(changes(t, `{"scanner":null}`)))
	assert.Equal(t, scanner.TrivyName, reopened.Effective().Scanner)
	assert.False(t, reopened.Overridden()[KeyScanner])
}

func TestScanSecretsSetting(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	store := Open(nil, dir, Values{ScanSecrets: true}, Validators{})

	require.NoError(t, store.Update(changes(t, `{"scan_secrets":false}`)))
	assert.False(t, store.Effective().ScanSecrets)
	assert.True(t, store.Overridden()[KeyScanSecrets])

	err := store.Update(changes(t, `{"scan_secrets":"no"}`))
	require.ErrorIs(t, err, ErrInvalidValue)

	// The choice survives a restart.
	reopened := Open(nil, dir, Values{ScanSecrets: true}, Validators{})
	assert.False(t, reopened.Effective().ScanSecrets)

	require.NoError(t, reopened.Update(changes(t, `{"scan_secrets":null}`)))
	assert.True(t, reopened.Effective().ScanSecrets)
	assert.False(t, reopened.Overridden()[KeyScanSecrets])
}

func TestUnknownSavedScannerIsDropped(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, FileName), []byte(`{"scanner":"clair","cleanup":true}`), 0o600))

	store := Open(nil, dir, Values{Scanner: scanner.TrivyName}, Validators{})
	assert.Equal(t, scanner.TrivyName, store.Effective().Scanner)
	assert.True(t, store.Effective().Cleanup, "other saved settings still apply")
}
