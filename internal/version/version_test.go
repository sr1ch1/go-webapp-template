package version

import "testing"

func TestInfoDefaults(t *testing.T) {
	info := Info()

	want := map[string]string{
		"version":    "dev",
		"commit":     "unknown",
		"build_time": "",
	}
	if len(info) != len(want) {
		t.Fatalf("Info() has %d keys, want %d", len(info), len(want))
	}
	for key, val := range want {
		if info[key] != val {
			t.Errorf("Info()[%q] = %q, want %q", key, info[key], val)
		}
	}
}

func TestInfoReflectsOverrides(t *testing.T) {
	origVersion, origCommit, origBuildTime := Version, Commit, BuildTime
	t.Cleanup(func() {
		Version, Commit, BuildTime = origVersion, origCommit, origBuildTime
	})

	Version = "1.2.3"
	Commit = "abc1234"
	BuildTime = "2026-01-02T03:04:05Z"

	want := map[string]string{
		"version":    "1.2.3",
		"commit":     "abc1234",
		"build_time": "2026-01-02T03:04:05Z",
	}
	info := Info()
	for key, val := range want {
		if info[key] != val {
			t.Errorf("Info()[%q] = %q, want %q", key, info[key], val)
		}
	}
}
