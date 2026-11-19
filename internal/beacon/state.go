package beacon

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"time"
)

// stateFile is the on-disk form of the per-name watermarks (§3.4).
//
// It is JSON with an explicit version because the watermark outlives the
// binary that wrote it: a client upgraded across a change to this format
// must refuse the file rather than misread it and silently reset every
// name's replay guard, which is the one thing the file exists to prevent.
type stateFile struct {
	Version int `json:"version"`
	// Watermarks maps a beacon name to the newest `published` accepted for
	// that name, in RFC 3339.
	Watermarks map[string]string `json:"watermarks"`
}

// stateVersion is the format this build writes and the only one it reads.
const stateVersion = 1

// LoadWatermarks reads the watermark file at path. A missing file is not an
// error: a client that has never read a beacon has nothing to guard, so the
// result is empty.
//
// A file that exists but cannot be understood is an error rather than an
// empty set. Treating a corrupt watermark as empty would disable the replay
// guard for every name, which is the failure mode §3.4 spends a paragraph
// on, so the caller is told instead of silently downgraded.
func LoadWatermarks(path string) (*Watermarks, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return NewWatermarks(nil), nil
	}
	if err != nil {
		return nil, fmt.Errorf("beacon: read %s: %w", path, err)
	}
	var st stateFile
	if err := json.Unmarshal(b, &st); err != nil {
		return nil, fmt.Errorf("beacon: parse %s: %w", path, err)
	}
	if st.Version != stateVersion {
		return nil, fmt.Errorf("beacon: %s has state version %d, want %d", path, st.Version, stateVersion)
	}
	seed := make(map[string]time.Time, len(st.Watermarks))
	for name, v := range st.Watermarks {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return nil, fmt.Errorf("beacon: %s: watermark for %q: %w", path, name, err)
		}
		seed[name] = t
	}
	return NewWatermarks(seed), nil
}

// Save writes the watermarks to path, replacing it atomically so a crash
// mid-write leaves the previous file rather than a truncated one. §3.4
// requires the watermark to be written *before* that name's relays are
// adopted: a crash between the two then leaves a client that refuses the
// old record for that name, rather than one that accepts both.
func (w *Watermarks) Save(path string) error {
	st := stateFile{Version: stateVersion, Watermarks: make(map[string]string)}
	for name, t := range w.Snapshot() {
		st.Watermarks[name] = t.UTC().Format(time.RFC3339)
	}
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return fmt.Errorf("beacon: encode state: %w", err)
	}
	b = append(b, '\n')
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".*")
	if err != nil {
		return fmt.Errorf("beacon: %w", err)
	}
	name := tmp.Name()
	defer func() {
		// Best-effort cleanup on any path that did not rename.
		if _, err := os.Stat(name); err == nil {
			os.Remove(name)
		}
	}()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return fmt.Errorf("beacon: write %s: %w", name, err)
	}
	// The file is 0600 like the other client secrets: it names relays and
	// their publication times, which is the deployment's layout.
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return fmt.Errorf("beacon: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("beacon: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("beacon: %w", err)
	}
	if err := os.Rename(name, path); err != nil {
		return fmt.Errorf("beacon: rename %s: %w", name, err)
	}
	if d, err := os.Open(dir); err == nil {
		// fsync the directory so the rename itself is durable, not just the
		// bytes. Failure here is not fatal: the write succeeded, and losing
		// the rename to a crash costs one re-read.
		d.Sync()
		d.Close()
	}
	return nil
}
