package diag

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ack is the relay's answer once it kept an upload (§11.4).
const ack = "ok\n"

// connBase stubs the net.Conn methods the engine's bridge does not use.
type connBase struct{}

func (connBase) LocalAddr() net.Addr              { return addr{} }
func (connBase) RemoteAddr() net.Addr             { return addr{} }
func (connBase) SetDeadline(time.Time) error      { return nil }
func (connBase) SetReadDeadline(time.Time) error  { return nil }
func (connBase) SetWriteDeadline(time.Time) error { return nil }

type addr struct{}

func (addr) Network() string { return "diagnostics" }
func (addr) String() string  { return "diagnostics" }

// UploadConn is the client's end of a diagnostics stream, as a connection
// the engine's bridge copies to the stream: reading it yields the upload,
// and writing it takes the relay's answer. Once the relay acknowledged the
// upload and the stream finished, Close calls the commit function from
// Journal.Pending.
type UploadConn struct {
	connBase
	mu     sync.Mutex
	data   []byte
	reply  []byte
	commit func() error
	ok     bool
	closed bool
}

// NewUploadConn uploads data, calling commit once the relay kept it.
func NewUploadConn(data []byte, commit func() error) *UploadConn {
	return &UploadConn{data: data, commit: commit}
}

func (c *UploadConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.data) == 0 {
		return 0, io.EOF
	}
	n := copy(p, c.data)
	c.data = c.data[n:]
	return n, nil
}

func (c *UploadConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.reply)+len(p) > len(ack) {
		return 0, errors.New("diag: unexpected reply")
	}
	c.reply = append(c.reply, p...)
	return len(p), nil
}

// CloseWrite is the relay's FIN.
func (c *UploadConn) CloseWrite() error { return nil }

// Close ends the upload gracefully: the stream finished in both
// directions, and the upload is committed if the relay acknowledged it.
// (The engine's bridge may close without CloseWrite once the stream is
// done.)
func (c *UploadConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if string(c.reply) != ack {
		return errors.New("diag: upload not acknowledged")
	}
	c.ok = true
	return c.commit()
}

// Abort abandons the upload, which stays in the journal.
func (c *UploadConn) Abort() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
}

// Acknowledged reports whether the relay kept the upload.
func (c *UploadConn) Acknowledged() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ok
}

// A Store keeps diagnostics uploads under a directory, one file per
// upload in a subdirectory per account, within per-upload and per-account
// size limits. It is safe for concurrent use.
type Store struct {
	Dir string
	// MaxUpload and MaxAccount bound one upload and an account's
	// directory (defaults 8 MiB and 64 MiB). Older files are not pruned:
	// once an account's directory is full, its uploads are refused until
	// the operator clears it.
	MaxUpload, MaxAccount int64

	mu sync.Mutex
}

// Create starts an upload for account from the client at lease. The name
// must be a safe path element (gateway account names are).
func (s *Store) Create(account, lease string, now time.Time) (*SinkConn, error) {
	if account == "" || account == "." || account == ".." || filepath.Base(account) != account {
		return nil, fmt.Errorf("diag: unusable account name %q", account)
	}
	maxUpload, maxAccount := s.MaxUpload, s.MaxAccount
	if maxUpload <= 0 {
		maxUpload = 8 << 20
	}
	if maxAccount <= 0 {
		maxAccount = 64 << 20
	}
	dir := filepath.Join(s.Dir, account)
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	used, err := dirSize(dir)
	if err != nil {
		return nil, err
	}
	if used >= maxAccount {
		return nil, fmt.Errorf("diag: account %s holds %d bytes of diagnostics, its limit", account, used)
	}
	name := filepath.Join(dir, fmt.Sprintf("%s-%s.jsonl", now.UTC().Format("20060102T150405.000Z"), lease))
	f, err := os.OpenFile(name+".part", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	return &SinkConn{f: f, name: name, max: min(maxUpload, maxAccount-used), kept: make(chan struct{})}, nil
}

func dirSize(dir string) (int64, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var n int64
	for _, e := range entries {
		if info, err := e.Info(); err == nil {
			n += info.Size()
		}
	}
	return n, nil
}

// SinkConn is the relay's end of a diagnostics stream: writing it fills
// the upload's file, and once the client finished (CloseWrite) and the
// file is in place, reading it yields the acknowledgement.
type SinkConn struct {
	connBase
	f    *os.File
	name string
	max  int64

	mu      sync.Mutex
	size    int64
	kept    chan struct{} // closed once the file is in place, or on Close
	isKept  bool
	closed  bool
	replied bool
}

// Name is the upload's file, once kept.
func (c *SinkConn) Name() string { return c.name }

// Size is how many bytes the upload holds so far.
func (c *SinkConn) Size() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.size
}

func (c *SinkConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.isKept {
		return 0, net.ErrClosed
	}
	if c.size+int64(len(p)) > c.max {
		return 0, fmt.Errorf("diag: upload exceeds %d bytes", c.max)
	}
	n, err := c.f.Write(p)
	c.size += int64(n)
	return n, err
}

// CloseWrite is the client's FIN: the upload is complete.
func (c *SinkConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.isKept {
		return net.ErrClosed
	}
	if err := c.f.Sync(); err != nil {
		return err
	}
	if err := c.f.Close(); err != nil {
		return err
	}
	if err := os.Rename(c.name+".part", c.name); err != nil {
		return err
	}
	c.isKept = true
	close(c.kept)
	return nil
}

// Read blocks until the upload is kept, then yields the acknowledgement.
func (c *SinkConn) Read(p []byte) (int, error) {
	<-c.kept
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.isKept {
		return 0, net.ErrClosed
	}
	if c.replied {
		return 0, io.EOF
	}
	c.replied = true
	return copy(p, ack), nil
}

// Close abandons an upload that was not kept.
func (c *SinkConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if !c.isKept {
		c.f.Close()
		os.Remove(c.name + ".part")
		close(c.kept)
	}
	return nil
}

// Kept reports whether the upload was stored.
func (c *SinkConn) Kept() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isKept
}
