package diag

import (
	"bytes"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
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

	// An account full of files that are not uploads is refused: only
	// uploads are pruned.
	os.WriteFile(filepath.Join(dir, "friend", "notes.txt"), make([]byte, 3<<10), 0o600)
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

func dirSize(t *testing.T, dir string) (n int64) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if info, err := e.Info(); err == nil { // else pruned meanwhile
			n += info.Size()
		}
	}
	return n
}

// storedSize is what dir holds besides uploads in progress.
func storedSize(t *testing.T, dir string) (n int64) {
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if info, err := e.Info(); err == nil && filepath.Ext(e.Name()) != ".part" {
			n += info.Size()
		}
	}
	return n
}

func upload(t *testing.T, s *Store, lease string, now time.Time, size int) {
	t.Helper()
	c, err := s.Create("friend", lease, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if err := c.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	c.Close()
}

// TestStorePrunesOldest fills an account: the oldest uploads make room
// for the newest, and nothing else is deleted.
func TestStorePrunesOldest(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir, MaxUpload: 2 << 10, MaxAccount: 4 << 10}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	os.MkdirAll(filepath.Join(dir, "friend"), 0o700)
	os.WriteFile(filepath.Join(dir, "friend", "notes.txt"), make([]byte, 512), 0o600)
	for i := range 6 {
		upload(t, s, "10.77.0.2", now.Add(time.Duration(i)*time.Second), 1<<10)
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "friend"))
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	want := []string{"20261109T120003.000Z-10.77.0.2.jsonl", "20261109T120004.000Z-10.77.0.2.jsonl",
		"20261109T120005.000Z-10.77.0.2.jsonl", "notes.txt"}
	if !slices.Equal(names, want) {
		t.Fatalf("account holds %v, want %v", names, want)
	}
	if used := dirSize(t, filepath.Join(dir, "friend")); used > 4<<10 {
		t.Fatalf("account holds %d bytes", used)
	}
	// The operator clearing files is noticed at the next upload.
	os.Remove(filepath.Join(dir, "friend", want[0]))
	upload(t, s, "10.77.0.2", now.Add(10*time.Second), 1<<10)
	if entries, _ := os.ReadDir(filepath.Join(dir, "friend")); len(entries) != 4 {
		t.Fatalf("an upload pruned what the operator had already freed: %v", entries)
	}
}

// TestStoreQuotaConcurrent runs uploads that together exceed an account:
// stored uploads are pruned for them, uploads in progress never are, the
// account stays within MaxAccount throughout, and a refused upload's
// bytes are released.
func TestStoreQuotaConcurrent(t *testing.T) {
	dir := t.TempDir()
	const maxAccount = 5 << 10
	s := &Store{Dir: dir, MaxUpload: 2 << 10, MaxAccount: maxAccount, MaxActive: 8}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	upload(t, s, "10.77.0.9", now, 1<<10)

	var sinks []*SinkConn
	for i := range 3 {
		c, err := s.Create("friend", fmt.Sprintf("10.77.0.%d", i+2), now.Add(time.Second))
		if err != nil {
			t.Fatalf("upload %d refused: %v", i, err)
		}
		sinks = append(sinks, c)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	kept := 0
	for _, c := range sinks {
		wg.Go(func() {
			buf := make([]byte, 256)
			for c.Size() < 2<<10 {
				if _, err := c.Write(buf); err != nil {
					c.Close() // refused: the engine resets the stream
					return
				}
				s.mu.Lock() // pruning and charges happen under it; writes follow charges
				used := storedSize(t, filepath.Join(dir, "friend"))
				s.mu.Unlock()
				if used > maxAccount {
					t.Errorf("account holds %d bytes, past its %d limit", used, maxAccount)
				}
			}
			if err := c.CloseWrite(); err != nil {
				t.Error(err)
			}
			mu.Lock()
			kept++
			mu.Unlock()
		})
	}
	wg.Wait()
	// Together they need 6 KiB in progress of 5: some ran out of room
	// while others were in progress (all of them, possibly, with limits
	// this small), or one finished first. What
	// remains is whole uploads, within the limit, and the oldest went
	// first.
	used := dirSize(t, filepath.Join(dir, "friend"))
	_, err := os.Stat(filepath.Join(dir, "friend", "20261109T120000.000Z-10.77.0.9.jsonl"))
	if old := err == nil; old {
		used -= 1 << 10
		if used > 4<<10 {
			t.Fatal("a newer upload was pruned before the oldest")
		}
	}
	if used > maxAccount || used%(2<<10) != 0 || used > int64(kept)*(2<<10) {
		t.Fatalf("account holds %d bytes of new uploads after %d of 3 were kept", used, kept)
	}
	// The refused upload's charge was released.
	upload(t, s, "10.77.0.2", now.Add(2*time.Second), 2<<10)
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

// TestStoreFailedUploadPrunesNothing: an upload that needs older uploads'
// room but never finishes leaves them all in place.
func TestStoreFailedUploadPrunesNothing(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir, MaxUpload: 2 << 10, MaxAccount: 4 << 10, Idle: 50 * time.Millisecond}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	for i := range 3 {
		upload(t, s, "10.77.0.2", now.Add(time.Duration(i)*time.Second), 1<<10)
	}
	names := func() (n []string) {
		entries, _ := os.ReadDir(filepath.Join(dir, "friend"))
		for _, e := range entries {
			n = append(n, e.Name())
		}
		return n
	}
	before := names()

	aborted, err := s.Create("friend", "10.77.0.2", now.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aborted.Write(make([]byte, 2<<10)); err != nil {
		t.Fatal(err)
	}
	aborted.Close()
	stalled, _ := s.Create("friend", "10.77.0.3", now.Add(11*time.Second))
	stalled.Write(make([]byte, 2<<10))
	if _, err := stalled.Read(make([]byte, 8)); err == nil || !stalled.Expired() {
		t.Fatal("the stalled upload was not abandoned")
	}
	if after := names(); !slices.Equal(before, after) {
		t.Fatalf("failed uploads changed the account from %v to %v", before, after)
	}

	// Kept, the same upload displaces the oldest, and only as much as
	// it needs.
	upload(t, s, "10.77.0.2", now.Add(20*time.Second), 2<<10)
	if after := names(); len(after) != 3 || slices.Contains(after, before[0]) || !slices.Contains(after, before[1]) {
		t.Fatalf("account holds %v", after)
	}
}

// TestStoreBoundsFileCount: tiny uploads cannot pile up files, and empty
// ones are refused.
func TestStoreBoundsFileCount(t *testing.T) {
	dir := t.TempDir()
	s := &Store{Dir: dir, MaxFiles: 5}
	now := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	for i := range 50 {
		c, err := s.Create("friend", "10.77.0.2", now.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if i%2 == 0 {
			if err := c.CloseWrite(); err == nil {
				t.Fatal("an empty upload was kept")
			}
		} else {
			c.Write([]byte("{}\n"))
			if err := c.CloseWrite(); err != nil {
				t.Fatal(err)
			}
		}
		c.Close()
	}
	entries, _ := os.ReadDir(filepath.Join(dir, "friend"))
	if len(entries) != 5 || entries[4].Name() != "20261109T120049.000Z-10.77.0.2.jsonl" {
		t.Fatalf("account holds %d files, newest %s", len(entries), entries[len(entries)-1].Name())
	}
}

// TestJournalSurvivesFailedRewrite: when the spool cannot be rewritten (a
// full disk, a read-only directory), logging goes on without a panic and
// the journal stays bounded; once it can, the file is whole again.
func TestJournalSurvivesFailedRewrite(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root writes to read-only directories")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "journal.jsonl")
	j, err := OpenJournal(path, "relay-a", 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer j.Close()
	log := slog.New(j.Handler())
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(dir, 0o700)
	for i := range 500 { // forces several rewrites, which fail
		log.Info("record", "i", i)
	}
	if _, err := os.Stat(path + ".tmp"); err == nil {
		t.Fatal("a failed rewrite left its temporary file")
	}
	if data, _ := j.Pending(); len(data) > 4096 || !strings.Contains(string(data), `"i":499`) {
		t.Fatalf("journal holds %d bytes", len(data))
	}
	os.Chmod(dir, 0o700)
	for i := range 200 {
		log.Info("record", "j", i)
	}
	data, _ := j.Pending()
	onDisk, _ := os.ReadFile(path)
	if !strings.Contains(string(data), `"j":199`) || !bytes.Equal(append(bytes.Clone(j.header), data...), onDisk) {
		t.Fatalf("after recovery the file holds %d bytes, the journal %d", len(onDisk), len(data))
	}
}
