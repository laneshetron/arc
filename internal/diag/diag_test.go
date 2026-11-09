package diag

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJournalSurvivesRestarts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, err := OpenJournal(path, 0)
	if err != nil {
		t.Fatal(err)
	}
	slog.New(j.Handler()).Debug("first run", "carrier", "wlan0/tls")
	j.Close()
	// A run that died mid-record leaves a partial line, which is dropped.
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	f.WriteString(`{"partial":`)
	f.Close()

	j, err = OpenJournal(path, 0)
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
	j, _ := OpenJournal(path, 0)
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
		!strings.Contains(string(rest), "two") || !bytes.Equal(rest, onDisk) {
		t.Fatalf("uploaded %q, left %q, file %q", data, rest, onDisk)
	}
}

func TestJournalBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "journal.jsonl")
	j, _ := OpenJournal(path, 4096)
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
