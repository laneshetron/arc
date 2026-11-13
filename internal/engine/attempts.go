package engine

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/laneshetron/arc/internal/carrier/stream"
	"github.com/laneshetron/arc/internal/session"
)

// Attempt lines are rate limited: anyone can send handshakes and open TLS
// connections, and the log must not become a way to fill the disk.
const (
	attemptLinesPerMinute = 60
	attemptPeers          = 4096 // TLS carriers' peers remembered for session lines
	attemptPeerLinger     = 2 * time.Minute
)

// AttemptLog logs what a relay sees of clients that have not, or not yet,
// authenticated: handshakes that never completed or failed, and TLS
// connections, whether they failed before becoming a carrier or ended
// after. Together with a client's journal, these show where a blocked
// connection dies: for example, a handshake the client kept resending
// reached the relay, but the relay's answers did not reach the client.
//
// Lines past attemptLinesPerMinute are dropped; the next line logged
// counts them as "suppressed". An AttemptLog is safe for concurrent use.
type AttemptLog struct {
	log *slog.Logger

	mu         sync.Mutex
	tokens     float64
	at         time.Time
	suppressed int
	peers      map[netip.AddrPort]attemptPeer // TLS carrier address -> TCP peer
}

type attemptPeer struct {
	peer   netip.AddrPort
	closed time.Time // zero while the carrier is open
}

// NewAttemptLog returns an AttemptLog writing to log.
func NewAttemptLog(log *slog.Logger) *AttemptLog {
	return &AttemptLog{log: log, tokens: attemptLinesPerMinute, peers: make(map[netip.AddrPort]attemptPeer)}
}

// allow takes a line from the rate limit, returning how many lines were
// suppressed before it, or false if this one is suppressed too.
func (a *AttemptLog) allow(now time.Time) (int, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.at.IsZero() {
		a.tokens = min(attemptLinesPerMinute, a.tokens+now.Sub(a.at).Minutes()*attemptLinesPerMinute)
	}
	a.at = now
	if a.tokens < 1 {
		a.suppressed++
		return 0, false
	}
	a.tokens--
	n := a.suppressed
	a.suppressed = 0
	return n, true
}

func (a *AttemptLog) line(level slog.Level, msg string, args ...any) {
	n, ok := a.allow(time.Now())
	if !ok {
		return
	}
	if n > 0 {
		args = append(args, "suppressed", n)
	}
	a.log.Log(context.Background(), level, msg, args...)
}

// TLS is a stream.ListenerOptions.Report (or FrontOptions.Report).
func (a *AttemptLog) TLS(r stream.ConnReport) {
	if r.Addr.IsValid() {
		a.notePeer(r.Addr, r.Peer, r.Open)
	}
	if r.Open {
		return
	}
	args := []any{"peer", r.Peer, "seconds", seconds(r.Duration), "bytes_in", r.BytesIn, "bytes_out", r.BytesOut}
	if r.Hello {
		args = append(args, "sni", r.ServerName, "alpn", r.ALPN)
	}
	if r.Err != nil {
		args = append(args, "err", r.Err)
	}
	if r.Addr.IsValid() {
		a.line(slog.LevelInfo, "tls carrier closed", append(args, "carrier", r.Addr)...)
		return
	}
	// Where it stopped: nothing arrived, a ClientHello did not finish
	// arriving (or did not parse), the handshake failed after the
	// relay's answer, or it finished with an ALPN the relay doesn't carry.
	stage := "tcp"
	switch {
	case errors.Is(r.Err, stream.ErrALPN):
		stage = "alpn"
	case r.Hello:
		stage = "server_hello"
	case r.BytesIn > 0:
		stage = "client_hello"
	}
	a.line(slog.LevelInfo, "tls connection failed", append(args, "stage", stage)...)
}

func (a *AttemptLog) notePeer(addr, peer netip.AddrPort, open bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !open {
		if e, ok := a.peers[addr]; ok {
			e.closed = time.Now()
			a.peers[addr] = e
		}
		return
	}
	if len(a.peers) >= attemptPeers {
		now := time.Now()
		for k, e := range a.peers {
			if !e.closed.IsZero() && now.Sub(e.closed) > attemptPeerLinger {
				delete(a.peers, k)
			}
		}
		if len(a.peers) >= attemptPeers {
			return // the session's lines show the carrier's address instead
		}
	}
	a.peers[addr] = attemptPeer{peer: peer}
}

// source names a session's client address for the log: the TCP peer of a
// TLS carrier if it is remembered, and which carrier it is.
func (a *AttemptLog) source(addr netip.AddrPort) (netip.AddrPort, string) {
	if !stream.IsStreamAddr(addr) {
		return addr, "udp"
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if e, ok := a.peers[addr]; ok {
		return e.peer, "tls"
	}
	return addr, "tls"
}

// established logs a session's authentication, which is not rate limited.
func (a *AttemptLog) established(s *session.RelaySession, now time.Time, args ...any) {
	h := s.Handshake()
	from, carrier := a.source(s.Addr(now))
	a.log.Info("session established", append([]any{"client", from, "carrier", carrier,
		"handshake_seconds", seconds(h.Established.Sub(h.Started)), "init_resends", h.Resends}, args...)...)
}

// unestablished logs a session that closed before it authenticated.
func (a *AttemptLog) unestablished(s *session.RelaySession, err error) {
	h := s.Handshake()
	from, carrier := a.source(h.From)
	args := []any{"client", from, "carrier", carrier, "seconds", seconds(time.Since(h.Started)),
		"init_resends", h.Resends, "reason", err}
	if errors.Is(err, session.ErrAuthFailed) {
		a.line(slog.LevelInfo, "handshake rejected: unknown token", args...)
		return
	}
	a.line(slog.LevelInfo, "handshake not completed", args...)
}

// failed logs a HANDSHAKE_INIT the relay could not answer.
func (a *AttemptLog) failed(e session.HandshakeFailed) {
	from, carrier := a.source(e.From)
	a.line(slog.LevelInfo, "handshake failed: not for this relay's key, or corrupted",
		"client", from, "carrier", carrier, "err", e.Err)
}

func seconds(d time.Duration) float64 { return d.Round(10 * time.Millisecond).Seconds() }
