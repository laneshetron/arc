package engine

import (
	"context"
	"errors"
	"io"
	"net"
	"time"

	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// streamSession is the stream API common to session.Client and
// session.RelaySession (spec §11.3).
type streamSession interface {
	StreamWrite(now time.Time, id uint32, p []byte) (int, error)
	StreamRead(now time.Time, id uint32, p []byte) (int, error)
	StreamCloseWrite(now time.Time, id uint32) error
	StreamReset(now time.Time, id uint32, code wire.ErrorCode)
	StreamInfo(id uint32) session.StreamInfo
}

// halfCloser is a TCP connection: the application's, accepted by the
// client's userspace stack, or the destination's, dialed by the relay.
type halfCloser interface {
	net.Conn
	CloseWrite() error
}

const (
	bridgeReadSize  = 32 << 10
	bridgeWriteSize = 64 << 10
)

// bridgeEvent is news from a bridge's goroutines: bytes read from the
// connection (with the read's error, io.EOF at its end), or a finished
// write to it.
type bridgeEvent struct {
	b     *bridge
	data  []byte
	err   error
	wrote bool
}

// bridge copies bytes between a TCP connection and a session stream. The
// engine loop owns its state and the session; a reader and a writer
// goroutine block on the connection, and talk to the loop only through
// events and two channels of capacity one, so the loop never blocks on
// them. Each holds at most one chunk at a time: the reader waits for
// credit after each read, and the writer gets a chunk only when idle, so
// backpressure reaches both TCP connections through the stream's flow
// control.
type bridge struct {
	id    uint32
	sess  streamSession
	conn  halfCloser
	abort func() // ends conn with a reset
	// forget, if set, removes the bridge from its owner's table when it
	// finishes.
	forget func()

	toConn chan []byte   // nil asks for CloseWrite
	credit chan struct{} // lets the reader read again
	done   chan struct{}

	pending    []byte // read from conn, not yet accepted by the stream
	readEOF    bool   // conn ended; the stream's FIN follows pending
	finSent    bool
	writing    bool // the writer holds a chunk
	finWritten bool // the writer has (or holds) the CloseWrite
	doneSeen   bool // the stream finished; close once the writer is idle
	finished   bool
}

func newBridge(id uint32, sess streamSession, conn halfCloser, abort func()) *bridge {
	return &bridge{id: id, sess: sess, conn: conn, abort: abort,
		toConn: make(chan []byte, 1), credit: make(chan struct{}, 1), done: make(chan struct{})}
}

func (b *bridge) start(ctx context.Context, events chan<- bridgeEvent) {
	go func() {
		for {
			buf := make([]byte, bridgeReadSize)
			n, err := b.conn.Read(buf)
			select {
			case events <- bridgeEvent{b: b, data: buf[:n], err: err}:
			case <-b.done:
				return
			case <-ctx.Done():
				return
			}
			if err != nil {
				return
			}
			select {
			case <-b.credit:
			case <-b.done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
	go func() {
		for {
			var data []byte
			select {
			case data = <-b.toConn:
			case <-b.done:
				return
			case <-ctx.Done():
				return
			}
			var err error
			if data == nil {
				err = b.conn.CloseWrite()
			} else {
				_, err = b.conn.Write(data)
			}
			select {
			case events <- bridgeEvent{b: b, wrote: true, err: err}:
			case <-b.done:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// handle applies an event and returns whether the bridge finished.
func (b *bridge) handle(now time.Time, e bridgeEvent) bool {
	if b.finished {
		return true
	}
	if e.wrote {
		b.writing = false
		if e.err != nil {
			return b.fail(now)
		}
		if b.doneSeen {
			return b.finish(false)
		}
		return b.service(now)
	}
	b.pending = e.data
	switch {
	case e.err == nil:
	case errors.Is(e.err, io.EOF):
		b.readEOF = true
	default:
		return b.fail(now) // reset or failed: so is the stream
	}
	if len(b.pending) == 0 && !b.readEOF {
		b.credit <- struct{}{}
	}
	return b.service(now)
}

// service moves what it can in both directions and returns whether the
// bridge finished.
func (b *bridge) service(now time.Time) bool {
	if b.finished {
		return true
	}
	if !b.writing && !b.finWritten && !b.doneSeen {
		buf := make([]byte, bridgeWriteSize)
		n, err := b.sess.StreamRead(now, b.id, buf)
		switch {
		case n > 0:
			b.writing = true
			b.toConn <- buf[:n]
		case errors.Is(err, io.EOF):
			b.writing, b.finWritten = true, true
			b.toConn <- nil
		case err != nil:
			return b.finish(true) // reset by the peer, or the session ended
		}
	}
	if len(b.pending) > 0 {
		n, err := b.sess.StreamWrite(now, b.id, b.pending)
		if err != nil {
			return b.finish(true)
		}
		b.pending = b.pending[n:]
		if len(b.pending) == 0 {
			b.pending = nil
			if !b.readEOF {
				b.credit <- struct{}{}
			}
		}
	}
	if b.readEOF && len(b.pending) == 0 && !b.finSent {
		b.finSent = true
		if err := b.sess.StreamCloseWrite(now, b.id); err != nil {
			return b.finish(true)
		}
	}
	if b.doneSeen {
		return false
	}
	info := b.sess.StreamInfo(b.id)
	switch {
	case info.Done && info.Err != nil:
		return b.finish(true)
	case info.Done:
		b.doneSeen = true
		if !b.writing {
			return b.finish(false)
		}
	}
	return false
}

// fail resets the stream after the connection failed.
func (b *bridge) fail(now time.Time) bool {
	b.sess.StreamReset(now, b.id, wire.CodeAborted)
	return b.finish(true)
}

// finish closes the connection, with a reset if abort, and stops the
// goroutines.
func (b *bridge) finish(abort bool) bool {
	if b.finished {
		return true
	}
	b.finished = true
	close(b.done)
	if b.forget != nil {
		b.forget()
	}
	if abort {
		b.abort()
	} else {
		b.conn.Close()
	}
	return true
}

// abortTCP closes a *net.TCPConn with a reset.
func abortTCP(c *net.TCPConn) func() {
	return func() {
		c.SetLinger(0)
		c.Close()
	}
}
