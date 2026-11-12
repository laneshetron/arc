package diag

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
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
//
// The limits bound what clients can make the relay keep: every upload is
// data a client chose, stored on the relay's disk. Each write of an upload
// is charged to its account as it arrives, so two uploads in progress
// cannot be charged for the same space. Once an upload is kept, the
// account's oldest stored uploads are deleted until it is back within
// MaxAccount and MaxFiles, so the operator keeps the newest diagnostics
// without clearing anything by hand; an upload that fails deletes
// nothing. While uploads are in progress, the directory may exceed
// MaxAccount by what they hold (at most MaxActive × MaxUpload). Empty
// uploads are refused.
type Store struct {
	Dir string
	// MaxUpload and MaxAccount bound one upload and an account's
	// directory (defaults 8 MiB and 64 MiB).
	MaxUpload, MaxAccount int64
	// MaxFiles bounds how many uploads an account keeps (default 256).
	MaxFiles int
	// MaxActive bounds an account's uploads in progress (default 4); a
	// client (a lease) has at most one.
	MaxActive int
	// Idle and Deadline abandon an upload that sent nothing for Idle
	// (default 2 minutes) or did not finish within Deadline (default 30
	// minutes).
	Idle, Deadline time.Duration

	mu       sync.Mutex
	accounts map[string]*account
}

// account is what an account's directory holds: stored uploads, oldest
// first (their names start with the time), which may be pruned; other
// files, which count but are not the Store's to delete; and the bytes
// written so far by uploads in progress.
type account struct {
	dir      string
	uploads  []storedUpload
	other    int64
	inflight int64
	leases   map[string]bool
	swept    bool // stale .part files removed
}

type storedUpload struct {
	name string
	size int64
}

// scan rereads the directory, which the operator may have changed.
func (a *account) scan() error {
	entries, err := os.ReadDir(a.dir)
	if err != nil {
		return err
	}
	a.uploads, a.other = a.uploads[:0], 0
	for _, e := range entries {
		info, err := e.Info()
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		switch filepath.Ext(e.Name()) {
		case ".part": // in progress: counted as it is written
		case ".jsonl":
			a.uploads = append(a.uploads, storedUpload{filepath.Join(a.dir, e.Name()), info.Size()})
		default:
			a.other += info.Size()
		}
	}
	slices.SortFunc(a.uploads, func(x, y storedUpload) int { return strings.Compare(x.name, y.name) })
	return nil
}

// charge accounts for n more bytes of an upload in progress. Stored
// uploads do not count against it, since the upload displaces them once
// kept; files that are not uploads, and other uploads in progress, do.
func (a *account) charge(n, max int64) error {
	if a.other+a.inflight+n > max {
		return fmt.Errorf("diag: account holds %d bytes of uploads in progress and other files, its limit",
			a.other+a.inflight)
	}
	a.inflight += n
	return nil
}

// keep adds a kept upload and deletes the oldest others until the stored
// uploads are within the limits. The newest upload is never deleted: it
// fits, since its bytes were charged.
func (a *account) keep(u storedUpload, maxBytes int64, maxFiles int) {
	a.uploads = append(a.uploads, u)
	stored := a.other
	for _, u := range a.uploads {
		stored += u.size
	}
	for len(a.uploads) > 1 && (stored > maxBytes || len(a.uploads) > maxFiles) {
		os.Remove(a.uploads[0].name) // gone already, or the next scan counts it again
		stored -= a.uploads[0].size
		a.uploads = a.uploads[1:]
	}
}

// Create starts an upload for account from the client at lease. The name
// must be a safe path element (gateway account names are).
func (s *Store) Create(name, lease string, now time.Time) (*SinkConn, error) {
	if name == "" || name == "." || name == ".." || filepath.Base(name) != name {
		return nil, fmt.Errorf("diag: unusable account name %q", name)
	}
	maxUpload, maxAccount, maxActive, maxFiles := s.MaxUpload, s.MaxAccount, s.MaxActive, s.MaxFiles
	if maxUpload <= 0 {
		maxUpload = 8 << 20
	}
	if maxAccount <= 0 {
		maxAccount = 64 << 20
	}
	if maxActive <= 0 {
		maxActive = 4
	}
	if maxFiles <= 0 {
		maxFiles = 256
	}
	idle, deadline := s.Idle, s.Deadline
	if idle <= 0 {
		idle = 2 * time.Minute
	}
	if deadline <= 0 {
		deadline = 30 * time.Minute
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.accounts == nil {
		s.accounts = map[string]*account{}
	}
	a := s.accounts[name]
	if a == nil {
		a = &account{dir: filepath.Join(s.Dir, name), leases: map[string]bool{}}
		s.accounts[name] = a
	}
	if a.leases[lease] {
		return nil, fmt.Errorf("diag: an upload from %s is in progress", lease)
	}
	if len(a.leases) >= maxActive {
		return nil, fmt.Errorf("diag: account %s has %d uploads in progress, its limit", name, len(a.leases))
	}
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return nil, err
	}
	if !a.swept { // left by a relay that stopped mid-upload
		parts, _ := filepath.Glob(filepath.Join(a.dir, "*.part"))
		for _, p := range parts {
			os.Remove(p)
		}
		a.swept = true
	}
	if err := a.scan(); err != nil {
		return nil, err
	}
	if a.other+a.inflight >= maxAccount {
		return nil, fmt.Errorf("diag: account %s is full of uploads in progress and other files", name)
	}
	file := filepath.Join(a.dir, fmt.Sprintf("%s-%s.jsonl", now.UTC().Format("20060102T150405.000Z"), lease))
	f, err := os.OpenFile(file+".part", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return nil, err
	}
	c := &SinkConn{f: f, name: file, max: maxUpload, kept: make(chan struct{}), idle: idle}
	a.leases[lease] = true
	c.charge = func(n int64) error {
		s.mu.Lock()
		defer s.mu.Unlock()
		return a.charge(n, maxAccount)
	}
	c.release = func(kept bool, size int64) {
		s.mu.Lock()
		defer s.mu.Unlock()
		a.inflight -= size
		if kept {
			a.keep(storedUpload{file, size}, maxAccount, maxFiles)
		}
		delete(a.leases, lease)
	}
	c.mu.Lock() // the timers' callbacks lock it too
	c.idleTimer = time.AfterFunc(idle, c.expire)
	c.deadlineTimer = time.AfterFunc(deadline, c.expire)
	c.mu.Unlock()
	return c, nil
}

// SinkConn is the relay's end of a diagnostics stream: writing it fills
// the upload's file, and once the client finished (CloseWrite) and the
// file is in place, reading it yields the acknowledgement. An upload that
// stalls or runs past its deadline is abandoned, as by Close.
type SinkConn struct {
	connBase
	f       *os.File
	name    string
	max     int64
	charge  func(n int64) error         // to the account, before writing n bytes
	release func(kept bool, size int64) // once kept or abandoned
	idle    time.Duration

	mu            sync.Mutex
	size          int64
	kept          chan struct{} // closed once the file is in place, or on Close
	isKept        bool
	closed        bool
	expired       bool
	replied       bool
	idleTimer     *time.Timer
	deadlineTimer *time.Timer
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
	if err := c.charge(int64(len(p))); err != nil {
		return 0, err
	}
	c.idleTimer.Reset(c.idle)
	c.size += int64(len(p)) // charged, whatever the write does
	return c.f.Write(p)
}

// CloseWrite is the client's FIN: the upload is complete. The file and its
// directory entry are synced before the acknowledgement, which lets the
// client drop what it uploaded.
func (c *SinkConn) CloseWrite() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed || c.isKept {
		return net.ErrClosed
	}
	if c.size == 0 {
		return errors.New("diag: empty upload")
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
	if err := syncDir(filepath.Dir(c.name)); err != nil {
		os.Remove(c.name) // unacknowledged: the client uploads it again
		return err
	}
	c.isKept = true
	c.stop()
	close(c.kept)
	return nil
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
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
	c.close()
	return nil
}

// expire abandons an upload that stalled or ran past its deadline.
func (c *SinkConn) expire() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed && !c.isKept {
		c.expired = true
		c.close()
	}
}

func (c *SinkConn) close() {
	if c.closed {
		return
	}
	c.closed = true
	if !c.isKept {
		c.f.Close()
		os.Remove(c.name + ".part")
		c.stop()
		close(c.kept)
	}
}

// stop releases the upload's charge and timers, once it was kept or
// abandoned; c.mu is held.
func (c *SinkConn) stop() {
	c.idleTimer.Stop()
	c.deadlineTimer.Stop()
	c.release(c.isKept, c.size)
}

// Kept reports whether the upload was stored.
func (c *SinkConn) Kept() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.isKept
}

// Expired reports whether the upload was abandoned because it stalled or
// ran past its deadline.
func (c *SinkConn) Expired() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.expired
}
