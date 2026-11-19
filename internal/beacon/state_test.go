package beacon

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatermarkFileRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "beacon-state.json")
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	w := NewWatermarks(map[string]time.Time{
		"b1._arcb.example.net": now,
		"b2._arcb.example.net": now.Add(-time.Hour),
	})
	if err := w.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadWatermarks(path)
	if err != nil {
		t.Fatal(err)
	}
	snap := got.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("%d watermarks", len(snap))
	}
	if !snap["b1._arcb.example.net"].Equal(now) {
		t.Errorf("b1 is %s, want %s", snap["b1._arcb.example.net"], now)
	}
	if !snap["b2._arcb.example.net"].Equal(now.Add(-time.Hour)) {
		t.Errorf("b2 is %s", snap["b2._arcb.example.net"])
	}
	// The guard must be live after loading, not just readable: a reloaded
	// watermark is the only thing that stops a replay across a restart.
	if got.Accept("b1._arcb.example.net", now.Add(-time.Minute)) {
		t.Error("a record older than the loaded watermark was accepted")
	}
}

func TestLoadWatermarksMissingFileIsEmpty(t *testing.T) {
	// A client that has never read a beacon has nothing to guard. Refusing
	// to start here would make first use impossible.
	w, err := LoadWatermarks(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(w.Snapshot()) != 0 {
		t.Errorf("%d watermarks from a missing file", len(w.Snapshot()))
	}
}

func TestLoadWatermarksRefusesCorruptState(t *testing.T) {
	// Silently treating an unreadable watermark as empty would disable the
	// replay guard for every name — the one thing §3.4 says it must prevent.
	for name, body := range map[string]string{
		"not json":      "{{{",
		"wrong version": `{"version":99,"watermarks":{}}`,
		"bad timestamp": `{"version":1,"watermarks":{"b1":"yesterday"}}`,
		"empty":         "",
	} {
		path := filepath.Join(t.TempDir(), "state.json")
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadWatermarks(path); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestSaveWatermarksIsAtomic(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "state.json")
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	first := NewWatermarks(map[string]time.Time{"b1": now})
	if err := first.Save(path); err != nil {
		t.Fatal(err)
	}
	second := NewWatermarks(map[string]time.Time{"b1": now.Add(time.Hour)})
	if err := second.Save(path); err != nil {
		t.Fatal(err)
	}
	got, err := LoadWatermarks(path)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Snapshot()["b1"].Equal(now.Add(time.Hour)) {
		t.Errorf("watermark is %s", got.Snapshot()["b1"])
	}
	// No temporary files may be left behind, or a crash loop fills the
	// profile directory with half-written state.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 {
		names := make([]string, len(entries))
		for i, e := range entries {
			names[i] = e.Name()
		}
		t.Errorf("directory has %v, want just the state file", names)
	}
}

func TestSaveWatermarksIsPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	w := NewWatermarks(map[string]time.Time{"b1": time.Now()})
	if err := w.Save(path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// The file names relays and their publication times, which is the
	// deployment's layout; it is 0600 like the other client secrets.
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode %o, want 600", perm)
	}
}

func TestSaveWatermarksIntoAMissingDirectory(t *testing.T) {
	// A clear error beats a panic when the profile directory is gone.
	path := filepath.Join(t.TempDir(), "absent", "state.json")
	w := NewWatermarks(map[string]time.Time{"b1": time.Now()})
	if err := w.Save(path); err == nil {
		t.Error("no error saving into a missing directory")
	}
}
