package stream

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"
)

func resetOp(op string) error {
	return &net.OpError{Op: op, Err: &os.SyscallError{Syscall: op, Err: syscall.ECONNRESET}}
}

func timeoutOp(op string) error {
	return &net.OpError{Op: op, Err: os.ErrDeadlineExceeded}
}

// tracked returns a trackingConn with fabricated counters.
func tracked(read, wrote int64) *trackingConn {
	c := &trackingConn{Conn: &fakeConn{}}
	c.read.Store(read)
	c.wrote.Store(wrote)
	return c
}

func TestClassifyConnect(t *testing.T) {
	if f := classifyConnect(timeoutOp("dial")); f.Mode != ModeConnectTimeout {
		t.Errorf("timeout dial classified %q", f.Mode)
	}
	if f := classifyConnect(resetOp("dial")); f.Mode != ModeConnectRefused {
		t.Errorf("refused dial classified %q", f.Mode)
	}
}

func TestClassifyHandshake(t *testing.T) {
	cases := []struct {
		name        string
		read, wrote int64
		err         error
		want        string
	}{
		{"nothing sent", 0, 0, io.EOF, ModeDied},
		{"reset after hello", 0, 300, resetOp("read"), ModeRSTAfterClientHello},
		{"timeout after hello", 0, 300, timeoutOp("read"), ModeTimeoutAfterClientHello},
		{"EOF after hello", 0, 300, io.EOF, ModeEOFAfterClientHello},
		{"killed after server hello", 64, 300, resetOp("read"), ModeKilledAfterServerHello},
		{"killed after server hello, timeout", 64, 300, timeoutOp("read"), ModeKilledAfterServerHello},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := classifyHandshake(tracked(tc.read, tc.wrote), tc.err)
			if f.Mode != tc.want {
				t.Errorf("classified %q, want %q", f.Mode, tc.want)
			}
			if f.Err != tc.err {
				t.Errorf("underlying error not preserved")
			}
		})
	}
}

func TestClassifyDeath(t *testing.T) {
	f := classifyDeath(tracked(500, 500), resetOp("read"))
	if f.Mode != ModeResetAtNBytes || f.At != 1000 {
		t.Errorf("reset death classified %+v", f)
	}
	f = classifyDeath(tracked(500, 500), timeoutOp("read"))
	if f.Mode != ModeTimeoutAtNBytes {
		t.Errorf("timeout death classified %q", f.Mode)
	}
	f = classifyDeath(tracked(500, 500), io.EOF)
	if f.Mode != ModeClosedAtNBytes {
		t.Errorf("EOF death classified %q", f.Mode)
	}
	if f.Unwrap() != io.EOF {
		t.Error("unwrap lost the underlying error")
	}
}

// A listener that reads some of the ClientHello and then resets the
// connection is the classic SNI blackhole: the client must report it as
// such, not as a generic error.
func TestClientReportsRSTAfterClientHello(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		io.CopyN(io.Discard, conn, 64) // part of the ClientHello crosses the wire
		if tcp, ok := conn.(*net.TCPConn); ok {
			tcp.SetLinger(0) // Close sends a RST
		}
		conn.Close()
	}()
	states := make(chan error, 4)
	c := Dial(ClientOptions{
		Addr: ln.Addr().String(), TLS: &tls.Config{ServerName: "127.0.0.1"},
		OnState: func(err error) { states <- err },
	})
	defer c.Close()
	select {
	case err := <-states:
		var f *Failure
		if !errors.As(err, &f) || f.Mode != ModeRSTAfterClientHello {
			t.Fatalf("client reported %v, want a %s Failure", err, ModeRSTAfterClientHello)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no dial result")
	}
}

// An established carrier whose TCP connection dies with a clean close is
// classified with the bytes it managed to exchange.
func TestClientClassifiesSessionDeath(t *testing.T) {
	ln, c, states := pair(t)
	c.WriteBatch([][]byte{bytes.Repeat([]byte{7}, 100)}, nil)
	_, from := readOne(t, ln)
	ln.mu.Lock()
	ln.links[from].close() // clean TLS close
	ln.mu.Unlock()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case err := <-states:
			var f *Failure
			if errors.As(err, &f) {
				if f.Mode != ModeClosedAtNBytes {
					t.Fatalf("session death classified %q", f.Mode)
				}
				if f.At <= 0 {
					t.Fatalf("death recorded %d bytes", f.At)
				}
				return
			}
			// nil (a reconnect) or unclassified notices: keep waiting
		case <-deadline:
			t.Fatal("no classified death")
		}
	}
}
