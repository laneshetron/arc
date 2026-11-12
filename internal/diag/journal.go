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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
)

// DefaultJournalSize bounds a journal's spool file.
const DefaultJournalSize = 4 << 20

// A Journal is an append-only spool of JSON log records awaiting upload to
// one relay. Its file starts with a header line naming that relay, then
// holds the records. It is safe for concurrent use.
type Journal struct {
	path   string
	max    int
	header []byte

	mu sync.Mutex
	// data mirrors the file's records, which are rewritten only when their
	// head is dropped; dropped counts every byte ever dropped from the
	// head, so that a Pending snapshot's commit drops no more than it
	// covered.
	data    []byte
	dropped int64
	f       *os.File
	handler slog.Handler
	// discarded is what an earlier run left for another relay.
	discarded int
}

// journalHeader is a journal file's first line.
type journalHeader struct {
	Journal int    `json:"arc_journal"`
	Relay   string `json:"relay"`
}

// OpenJournal opens or creates the spool at path for the relay identified
// by relay (its public key), keeping what an earlier run left there for
// that relay, and bounds the records to max bytes (DefaultJournalSize if
// 0): past that, the oldest half is dropped. Records an earlier run kept
// for another relay, or in a file without a header, are discarded
// (Discarded says how many bytes), never uploaded to this one.
func OpenJournal(path, relay string, max int) (*Journal, error) {
	if max <= 0 {
		max = DefaultJournalSize
	}
	if relay == "" {
		return nil, errors.New("journal: no relay")
	}
	header, err := json.Marshal(journalHeader{Journal: 1, Relay: relay})
	if err != nil {
		return nil, err
	}
	owner, data, size, err := readSpool(path, max)
	if err != nil {
		return nil, fmt.Errorf("journal: %w", err)
	}
	j := &Journal{path: path, max: max, header: append(header, '\n'), data: data}
	if owner != relay {
		j.data, j.discarded = nil, int(min(size, 1<<30))
	}
	if err := j.rewrite(); err != nil {
		return nil, err
	}
	j.handler = slog.NewJSONHandler(j, &slog.HandlerOptions{Level: slog.LevelDebug})
	return j, nil
}

// readSpool reads a journal file's owner and its records, at most the
// newest max/2 bytes of them if they exceed max, without a partial record
// at either end. size is the file's size (0 if there is none).
func readSpool(path string, max int) (owner string, data []byte, size int64, err error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil, 0, nil
	}
	if err != nil {
		return "", nil, 0, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return "", nil, 0, err
	}
	size = info.Size()
	head := make([]byte, min(size, 1024))
	if _, err := io.ReadFull(f, head); err != nil {
		return "", nil, size, err
	}
	i := bytes.IndexByte(head, '\n')
	var h journalHeader
	if i < 0 || json.Unmarshal(head[:i], &h) != nil || h.Journal != 1 || h.Relay == "" {
		return "", nil, size, nil // not a journal this version wrote
	}
	start, trimmed := int64(i+1), false
	if size-start > int64(max) {
		start, trimmed = size-int64(max/2), true
	}
	data = make([]byte, size-start)
	if _, err := f.ReadAt(data, start); err != nil && !errors.Is(err, io.EOF) {
		return "", nil, size, err
	}
	if trimmed { // starts mid-record
		if k := bytes.IndexByte(data, '\n'); k >= 0 {
			data = data[k+1:]
		} else {
			data = nil
		}
	}
	if k := bytes.LastIndexByte(data, '\n'); k+1 < len(data) {
		data = data[:k+1] // an earlier run died mid-record
	}
	return h.Relay, data, size, nil
}

// Discarded is how many bytes OpenJournal dropped because an earlier run
// kept them for another relay (or in a format it does not know).
func (j *Journal) Discarded() int { return j.discarded }

// Handler returns a handler that records everything at debug level and
// above in the journal.
func (j *Journal) Handler() slog.Handler { return j.handler }

// Write appends one record; slog's JSON handler writes each in one call.
// The journal stays bounded in memory even when its file cannot be
// written (a full disk, say): the record is then kept in memory only, and
// the error returned, which slog drops. Logging never fails the client.
func (j *Journal) Write(p []byte) (int, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if len(p) > j.max/2 {
		return len(p), nil // never displaces the whole journal
	}
	var err error
	if len(j.data)+len(p) > j.max {
		j.dropHead(len(j.data) - j.max/2)
		err = j.rewrite()
	}
	j.data = append(j.data, p...)
	if err != nil {
		return 0, err
	}
	if _, err := j.f.Write(p); err != nil {
		return 0, fmt.Errorf("journal: %w", err)
	}
	return len(p), nil
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
// appending. If it fails, the journal keeps appending to the file it had
// (which then holds records the data no longer does, until a later
// rewrite succeeds); j.f is never left unusable.
func (j *Journal) rewrite() error {
	tmp := j.path + ".tmp"
	if err := os.WriteFile(tmp, append(bytes.Clone(j.header), j.data...), 0o600); err != nil {
		os.Remove(tmp)
		return fmt.Errorf("journal: %w", err)
	}
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		os.Remove(tmp)
		return fmt.Errorf("journal: %w", err)
	}
	if err := os.Rename(tmp, j.path); err != nil {
		f.Close()
		os.Remove(tmp)
		return fmt.Errorf("journal: %w", err)
	}
	if j.f != nil {
		j.f.Close()
	}
	j.f = f // the open file follows the rename
	return nil
}

// Tee returns a logger that writes to both handlers, e.g. the console at
// its usual level and a journal at debug level.
func Tee(console, journal slog.Handler) *slog.Logger {
	return slog.New(slog.NewMultiHandler(console, journal))
}
