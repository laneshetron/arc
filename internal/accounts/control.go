package accounts

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

// A Request is one operator command (self-service-accounts.md §3.2).
type Request struct {
	Op   string   `json:"op"` // add, remove, add-token, revoke, list
	Args []string `json:"args"`
	// Flags for add: relay access and a device cap.
	Relay      bool `json:"relay,omitempty"`
	MaxDevices int  `json:"max_devices,omitempty"`
}

// A Response answers a Request. Token is set by add-token. An Error
// may come with Output and Token, when the store did not confirm the
// change (ErrIndeterminate): they are what the change would have made.
type Response struct {
	Output string `json:"output,omitempty"`
	Token  string `json:"token,omitempty"`
	Error  string `json:"error,omitempty"`
}

// Do runs req against w: list reads the committed state; every other
// operation is one transaction, and succeeds only once the store has it.
func Do(ctx context.Context, w *Writer, req Request, now time.Time) Response {
	if req.Op == "list" {
		st := w.State()
		if st == nil {
			return Response{Error: "no accounts loaded yet (the writer has not acquired the lease)"}
		}
		return Response{Output: List(st)}
	}
	var out string
	var token []byte
	arg := func(i int) string {
		if i < len(req.Args) {
			return req.Args[i]
		}
		return ""
	}
	want := map[string]int{"add": 1, "remove": 1, "add-token": 1, "revoke": 1}
	n, ok := want[req.Op]
	if !ok {
		return Response{Error: fmt.Sprintf("unknown operation %q", req.Op)}
	}
	if len(req.Args) < n || len(req.Args) > n+1 || (req.Op != "add-token" && len(req.Args) != n) {
		return Response{Error: fmt.Sprintf("%s: wrong number of arguments", req.Op)}
	}
	err := w.Commit(ctx, func(st *State) (err error) {
		switch req.Op {
		case "add":
			out, err = AddAccount(st, arg(0), req.Relay, req.MaxDevices)
		case "remove":
			out, err = RemoveAccount(st, arg(0), now)
		case "add-token":
			out, token, err = AddToken(st, arg(0), arg(1), now)
		case "revoke":
			out, err = Revoke(st, arg(0), now)
		}
		return err
	})
	switch {
	case errors.Is(err, ErrIndeterminate):
		// Keep the token: the store may have its device.
		msg := err.Error() + "; run list to see whether it was"
		if token != nil {
			msg += ", and if the device is there, this is its token: it is not shown again"
		}
		return Response{Output: out, Token: string(token), Error: msg}
	case errors.Is(err, ErrUnavailable):
		return Response{Error: err.Error() + "; nothing changed"}
	case err != nil:
		return Response{Error: err.Error()}
	}
	return Response{Output: out, Token: string(token)}
}

// Control is the relay's control socket and writer lock, in one
// directory: the lock excludes a second writer on the host, a running
// relay or an offline command, and the socket takes commands while a
// relay runs.
type Control struct{ Dir string }

func (c Control) socket() string { return filepath.Join(c.Dir, "control.sock") }
func (c Control) lock() string   { return filepath.Join(c.Dir, "accounts.lock") }

// TokenFile is where the writer holding this directory's lock keeps its
// lease token (Writer.TokenFile).
func (c Control) TokenFile() string { return filepath.Join(c.Dir, "lease-token") }

// ErrLocked: another writer on this host holds the lock.
var ErrLocked = errors.New("accounts: another writer on this host holds the lock")

// Lock takes the writer lock without waiting.
func (c Control) Lock() (func(), error) {
	if err := os.MkdirAll(c.Dir, 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(c.lock(), os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrLocked
		}
		return nil, err
	}
	f.Truncate(0)
	f.WriteString(strconv.Itoa(os.Getpid()) + "\n")
	return func() { f.Close() }, nil
}

// Serve answers commands on the control socket until ctx is done. Only
// the socket's owner (root, for the relay) can connect: it is mode 0600
// in a 0700 directory.
func (c Control) Serve(ctx context.Context, w *Writer) error {
	os.Remove(c.socket())
	ln, err := net.Listen("unix", c.socket())
	if err != nil {
		return err
	}
	if err := os.Chmod(c.socket(), 0o600); err != nil {
		ln.Close()
		return err
	}
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go func() {
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(time.Minute))
			var req Request
			if err := json.NewDecoder(bufio.NewReader(conn)).Decode(&req); err != nil {
				json.NewEncoder(conn).Encode(Response{Error: "bad request: " + err.Error()})
				return
			}
			json.NewEncoder(conn).Encode(Do(ctx, w, req, time.Now()))
		}()
	}
}

// ErrNoRelay: nothing listens on the control socket.
var ErrNoRelay = errors.New("accounts: no relay on the control socket")

// Send sends req to a running relay's control socket.
func (c Control) Send(req Request) (Response, error) {
	conn, err := net.DialTimeout("unix", c.socket(), 5*time.Second)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ENOENT) {
			return Response{}, ErrNoRelay
		}
		return Response{}, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Minute))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return Response{}, err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return Response{}, err
	}
	return resp, nil
}
