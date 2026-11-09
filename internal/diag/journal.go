// Package diag keeps a client's diagnostics and carries them to the relay's
// operator (spec §11.4), so that a user on a network that misbehaves need
// not collect and send them by hand.
//
// The client writes its log, at debug level, to a Journal: a spool file
// that survives restarts, so a run that never connected is uploaded by the
// next one that does. Once a session is up, the engine uploads what the
// journal holds on a diagnostics stream (an UploadConn) and drops it from
// the spool once the relay confirms it kept it. The relay writes each
// upload to a file of its own (a Store).
package diag

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sync"
)

// DefaultJournalSize bounds a journal's spool file.
const DefaultJournalSize = 4 << 20

// A Journal is an append-only spool of JSON log records awaiting upload.
// It is safe for concurrent use.
type Journal struct {
	path string
	max  int

	mu sync.Mutex
	// data mirrors the file, which is rewritten only when its head is
	// dropped; dropped counts every byte ever dropped from the head, so
	// that a Pending snapshot's commit drops no more than it covered.
	data    []byte
	dropped int64
	f       *os.File
	handler slog.Handler
}

// OpenJournal opens or creates the spool at path, keeping what an earlier
// run left there, and bounds it to max bytes (DefaultJournalSize if 0):
// past that, the oldest half is dropped.
func OpenJournal(path string, max int) (*Journal, error) {
	if max <= 0 {
		max = DefaultJournalSize
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if i := bytes.LastIndexByte(data, '\n'); i+1 < len(data) {
		data = data[:i+1] // an earlier run died mid-record
	}
	j := &Journal{path: path, max: max, data: data}
	if err := j.rewrite(); err != nil {
		return nil, err
	}
	j.handler = slog.NewJSONHandler(j, &slog.HandlerOptions{Level: slog.LevelDebug})
	return j, nil
}

// Handler returns a handler that records everything at debug level and
// above in the journal.
func (j *Journal) Handler() slog.Handler { return j.handler }

// Write appends one record; slog's JSON handler writes each in one call.
func (j *Journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(p) > j.max/2 {
		return len(p), nil // never displaces the whole journal
	}
	if len(j.data)+len(p) > j.max {
		j.dropHead(len(j.data) - j.max/2)
		if err := j.rewrite(); err != nil {
			return 0, err
		}
	}
	j.data = append(j.data, p...)
	return j.f.Write(p)
}

// Pending returns what the journal holds, and a commit function that drops
// those bytes once they were uploaded. Records written meanwhile stay.
func (j *Journal) Pending() (data []byte, commit func() error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	data = bytes.Clone(j.data)
	end := j.dropped + int64(len(data))
	return data, func() error {
		j.mu.Lock()
		defer j.mu.Unlock()
		if n := end - j.dropped; n > 0 {
			j.dropHead(int(min(n, int64(len(j.data)))))
			return j.rewrite()
		}
		return nil
	}
}

// Close closes the spool file.
func (j *Journal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.f.Close()
}

// dropHead drops at least n bytes from the head, up to a record boundary.
func (j *Journal) dropHead(n int) {
	if n <= 0 {
		return
	}
	if n < len(j.data) {
		if i := bytes.IndexByte(j.data[n-1:], '\n'); i >= 0 {
			n += i
		} else {
			n = len(j.data)
		}
	}
	n = min(n, len(j.data))
	j.data = append(j.data[:0], j.data[n:]...)
	j.dropped += int64(n)
}

// rewrite replaces the file with data, atomically, and reopens it for
// appending.
func (j *Journal) rewrite() error {
	if j.f != nil {
		j.f.Close()
		j.f = nil
	}
	tmp := j.path + ".tmp"
	if err := os.WriteFile(tmp, j.data, 0o600); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	if err := os.Rename(tmp, j.path); err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	f, err := os.OpenFile(j.path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return fmt.Errorf("journal: %w", err)
	}
	j.f = f
	return nil
}

// Tee returns a logger that writes to both handlers, e.g. the console at
// its usual level and a journal at debug level.
func Tee(console, journal slog.Handler) *slog.Logger {
	return slog.New(slog.NewMultiHandler(console, journal))
}
