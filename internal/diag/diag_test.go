package diag

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestJournalSurvivesRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, err := OpenJournal(path, "relay-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	slog.New(j.Handler()).Debug("first run", "carrier", "wlan0/tls")
	j.Close()
	// A run that died mid-record leaves a partial line, which is dropped.
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"partial":`)
	f.Close()

	j, err = OpenJournal(path, "relay-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	slog.New(j.Handler()).Info("second run")
	data, _ := j.Pending()
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "first run") || !strings.Contains(lines[0], `"level":"DEBUG"`) ||
		!strings.Contains(lines[1], "second run") {
		t.Fatalf("journal = %q", data)
	}
}

func TestJournalCommitKeepsLaterRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, _ := OpenJournal(path, "relay-a", 0)
	defer j.Close()
	log := slog.New(j.Handler())
	log.Info("one")
	data, commit := j.Pending()
	log.Info("two") // written while the upload is in flight
	if err := commit(); err != nil {
		t.Fatal(err)
	}
	if err := commit(); err != nil { // idempotent
		t.Fatal(err)
	}
	rest, _ := j.Pending()
	onDisk, _ := os.ReadFile(path)
	if !strings.Contains(string(data), "one") || strings.Contains(string(rest), "one") ||
		!strings.Contains(string(rest), "two") || !bytes.Equal(append(bytes.Clone(j.header), rest...), onDisk) {
		t.Fatalf("uploaded %q, left %q, file %q", data, rest, onDisk)
	}
}

func TestJournalBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, _ := OpenJournal(path, "relay-a", 4096)
	defer j.Close()
	log := slog.New(j.Handler())
	_, commit := j.Pending() // covers nothing
	for i := range 500 {
		log.Info("record", "i", i)
	}
	data, _ := j.Pending()
	if len(data) > 4096 || !strings.HasSuffix(string(data), "\n") || !strings.HasPrefix(string(data), "{") ||
		!strings.Contains(string(data), `"i":499`) {
		t.Fatalf("bounded journal holds %d bytes: ...%q", len(data), data[max(0, len(data)-80):])
	}
	commit() // an old snapshot drops nothing the trim did not already
	if again, _ := j.Pending(); !bytes.Equal(again, data) {
		t.Fatal("a stale commit dropped records")
	}
}

func TestUploadAndStore(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir, MaxUpload: 1 << 10, MaxAccount: 3 << 10}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	committed := false
	up := NewUploadConn([]byte("line\n"), func() error { committed = true; return nil })
	sink, err := s.Create("friend", "10.77.0.2", now)
	if err != nil {
		t.Fatal(err)
	}
	// What the engine's bridges do, by hand: upload, FIN, ack, FIN.
	data, _ := io.ReadAll(up)
	sink.Write(data)
	if err := sink.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, _ := io.ReadAll(sink)
	up.Write(reply)
	up.CloseWrite()
	if err := up.Close(); err != nil || !committed || !up.Acknowledged() {
		t.Fatalf("upload not committed: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "friend", "20261109T120000.000Z-10.77.0.2.jsonl"))
	if err != nil || string(got) != "line\n" || sink.Name() == "" || !sink.Kept() {
		t.Fatalf("stored %q, %v", got, err)
	}

	// Without the acknowledgement, or aborted, nothing is committed.
	up = NewUploadConn([]byte("x"), func() error { t.Fatal("committed"); return nil })
	if up.Close() == nil {
		t.Fatal("an unacknowledged upload succeeded")
	}
	up = NewUploadConn([]byte("x"), func() error { t.Fatal("committed"); return nil })
	up.Write([]byte(ack))
	up.Abort()
	up.Close()

	// An abandoned upload leaves nothing; an oversized one is refused.
	sink, _ = s.Create("friend", "10.77.0.2", now.Add(time.Second))
	if _, err := sink.Write(make([]byte, 2<<10)); err == nil {
		t.Fatal("upload past MaxUpload accepted")
	}
	sink.Close()
	if _, err := sink.Read(make([]byte, 8)); err == nil {
		t.Fatal("an abandoned upload was acknowledged")
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "friend"))
	if len(entries) != 1 {
		t.Fatalf("abandoned upload left %d files", len(entries))
	}

	// A full account is refused.
	os.WriteFile(filepath.Join(dir, "friend", "big"), make([]byte, 3<<10), 0o600)
	if _, err := s.Create("friend", "10.77.0.2", now.Add(2*time.Second)); err == nil {
		t.Fatal("upload to a full account accepted")
	}
	for _, name := range []string{"", ".", "..", "a/b"} {
		if _, err := s.Create(name, "10.77.0.2", now); err == nil {
			t.Errorf("account %q accepted", name)
		}
	}
}

func TestJournalBoundToRelay(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, _ := OpenJournal(path, "relay-a", 0)
	slog.New(j.Handler()).Info("for a", "carrier", "wlan0/udp")
	j.Close()

	// The same spool, configured for another relay: nothing of relay A's
	// reaches it, now or once the client returns to A.
	j, err := OpenJournal(path, "relay-b", 0)
	if err != nil {
		t.Fatal(err)
	}
	if data, _ := j.Pending(); len(data) != 0 || j.Discarded() == 0 {
		t.Fatalf("relay B's journal holds %q (discarded %d)", data, j.Discarded())
	}
	slog.New(j.Handler()).Info("for b")
	j.Close()
	j, _ = OpenJournal(path, "relay-a", 0)
	defer j.Close()
	if data, _ := j.Pending(); len(data) != 0 {
		t.Fatalf("relay A's journal holds %q", data)
	}
	slog.New(j.Handler()).Info("for a again")
	j.Close()
	j, _ = OpenJournal(path, "relay-a", 0)
	if data, _ := j.Pending(); !strings.Contains(string(data), "for a again") || j.Discarded() != 0 {
		t.Fatalf("relay A's own records lost: %q", data)
	}

	// A file this version did not write (no header) is not uploaded.
	legacy := filepath.Join(t.TempDir(), "journal.jsonl")
	os.WriteFile(legacy, []byte(`{"msg":"old"}`+"\n"), 0o600)
	j, _ = OpenJournal(legacy, "relay-a", 0)
	defer j.Close()
	if data, _ := j.Pending(); len(data) != 0 {
		t.Fatalf("a headerless spool was kept: %q", data)
	}
}

func TestJournalTrimmedAtStartup(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, _ := OpenJournal(path, "relay-a", 1<<20)
	log := slog.New(j.Handler())
	for i := range 2000 {
		log.Info("record", "i", i)
	}
	j.Close()
	j, err := OpenJournal(path, "relay-a", 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	data, _ := j.Pending()
	if len(data) == 0 || len(data) > 4096 || !strings.HasPrefix(string(data), "{") ||
		!strings.HasSuffix(string(data), "\n") || !strings.Contains(string(data), `"i":1999`) {
		t.Fatalf("oversized spool opened with %d bytes: %q...", len(data), data[:min(len(data), 80)])
	}
	if info, _ := os.Stat(path); info.Size() > 4096+int64(len(j.header)) {
		t.Fatalf("spool file still %d bytes", info.Size())
	}
}

// TestStoreQuotaConcurrent fills an account's remaining space with
// concurrent uploads: each reserves its allowance when it starts, so
// together they stay within MaxAccount.
func TestStoreQuotaConcurrent(t *testing.T) {
	dir := t.TempDir()
	const maxAccount = 6 << 10 // 1 KiB stored, then 2, 2 and the last 1 reserved
	s := &Store{Dir: dir, MaxUpload: 2 << 10, MaxAccount: maxAccount, MaxActive: 8}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	os.MkdirAll(filepath.Join(dir, "friend"), 0o700)
	os.WriteFile(filepath.Join(dir, "friend", "old.jsonl"), make([]byte, 1<<10), 0o600)

	var sinks []*SinkConn
	for i := range 4 {
		c, err := s.Create("friend", fmt.Sprintf("10.77.0.%d", i+2), now)
		if i < 3 && err != nil {
			t.Fatalf("upload %d refused: %v", i, err)
		}
		if i == 3 {
			if err == nil {
				t.Fatal("an upload beyond the reserved space was accepted")
			}
			break
		}
		sinks = append(sinks, c)
	}
	var wg sync.WaitGroup
	for _, c := range sinks {
		wg.Go(func() {
			buf := make([]byte, 256)
			for {
				if _, err := c.Write(buf); err != nil {
					break
				}
			}
			if err := c.CloseWrite(); err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if used, _ := dirSize(filepath.Join(dir, "friend")); used > maxAccount {
		t.Fatalf("account holds %d bytes, past its %d limit", used, maxAccount)
	} else if used < maxAccount {
		t.Fatalf("account holds %d bytes; the uploads should have filled %d", used, maxAccount)
	}
	if _, err := s.Create("friend", "10.77.0.2", now.Add(time.Second)); err == nil {
		t.Fatal("upload to a full account accepted")
	}
	// An abandoned upload gives its reservation back.
	os.Remove(filepath.Join(dir, "friend", "old.jsonl"))
	c, err := s.Create("friend", "10.77.0.2", now.Add(2*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if _, err := s.Create("friend", "10.77.0.3", now.Add(3*time.Second)); err != nil {
		t.Fatalf("an abandoned upload kept its reservation: %v", err)
	}
}

func TestStoreActiveLimits(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir, MaxActive: 2}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	os.MkdirAll(filepath.Join(dir, "friend"), 0o700)
	stale := filepath.Join(dir, "friend", "20261108T000000.000Z-10.77.0.9.jsonl.part")
	os.WriteFile(stale, make([]byte, 100), 0o600)

	a, err := s.Create("friend", "10.77.0.2", now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(stale); err == nil {
		t.Fatal("a stale .part file survived")
	}
	if _, err := s.Create("friend", "10.77.0.2", now.Add(time.Millisecond)); err == nil {
		t.Fatal("a second upload from one client accepted")
	}
	if _, err := s.Create("friend", "10.77.0.3", now); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Create("friend", "10.77.0.4", now); err == nil {
		t.Fatal("an upload past the account's MaxActive accepted")
	}
	if _, err := s.Create("lane", "10.77.0.5", now); err != nil {
		t.Fatalf("another account was limited: %v", err)
	}
	a.Close()
	if _, err := s.Create("friend", "10.77.0.4", now); err != nil {
		t.Fatalf("a finished upload still counts: %v", err)
	}
}

// TestStoreStalledUploads abandons an upload that stops sending, and one
// that keeps sending past its deadline.
func TestStoreStalledUploads(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name           string
		idle, deadline time.Duration
		trickle        bool
	}{
		{"idle", 50 * time.Millisecond, time.Minute, false},
		{"deadline", time.Minute, 150 * time.Millisecond, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &Store{Dir: dir, Idle: tc.idle, Deadline: tc.deadline, MaxActive: 1}
			c, err := s.Create(tc.name, "10.77.0.2", now)
			if err != nil {
				t.Fatal(err)
			}
			c.Write([]byte("{}\n"))
			stop := make(chan struct{})
			defer close(stop)
			if tc.trickle {
				go func() {
					for {
						select {
						case <-stop:
							return
						case <-time.After(10 * time.Millisecond):
							c.Write([]byte("{}\n"))
						}
					}
				}()
			}
			read := make(chan error, 1)
			go func() { _, err := c.Read(make([]byte, 8)); read <- err }() // the bridge's reader
			select {
			case err := <-read:
				if err == nil || !c.Expired() || c.Kept() {
					t.Fatalf("stalled upload: read %v, expired %v", err, c.Expired())
				}
			case <-time.After(5 * time.Second):
				t.Fatal("a stalled upload was not abandoned")
			}
			if entries, _ := os.ReadDir(filepath.Join(dir, tc.name)); len(entries) != 0 {
				t.Fatalf("abandoned upload left %v", entries)
			}
			if _, err := s.Create(tc.name, "10.77.0.2", now.Add(time.Second)); err != nil {
				t.Fatalf("an abandoned upload kept its slot: %v", err)
			}
		})
	}
}
