package session

import (
	"errors"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

// TestHandshakeInfoWhenRepliesAreLost blocks the relay's answers: the
// sessions the client's INITs open close unauthenticated, each reporting
// where it came from and that the client kept resending its INIT, which
// tells the operator the replies are not getting through.
func TestHandshakeInfoWhenRepliesAreLost(t *testing.T) {
	n := newNetwork(t, 90, defaultRelayConfig(), ClientConfig{})
	n.down.down = true
	n.runFor(30 * time.Second)
	var closed []SessionClosed
	for _, e := range n.relayEvents {
		if e, ok := e.(SessionClosed); ok {
			closed = append(closed, e)
		}
	}
	if len(closed) == 0 {
		t.Fatal("no pending session closed")
	}
	for _, e := range closed {
		h := e.Session.Handshake()
		if !errors.Is(e.Err, ErrHandshakeTimeout) || h.From != n.clientAddr || h.Resends == 0 ||
			!h.Established.IsZero() || h.Started.IsZero() {
			t.Errorf("closed with %v, handshake %+v; want a timeout from %v with resends", e.Err, h, n.clientAddr)
		}
	}
}

// TestHandshakeInfoOnEstablish loses the relay's first answer: the
// session that authenticates reports the one resend and when it
// authenticated.
func TestHandshakeInfoOnEstablish(t *testing.T) {
	n := newNetwork(t, 91, defaultRelayConfig(), ClientConfig{})
	dropped := false
	n.tap = func(toRelay bool, d []byte) {
		n.down.down = !toRelay && d[0] == byte(wire.TypeHandshakeResp) && !dropped
		if n.down.down {
			dropped = true
		}
	}
	s := n.establish()
	h := s.Handshake()
	if h.From != n.clientAddr || h.Resends != 1 || h.Established.IsZero() || !h.Established.After(h.Started) {
		t.Errorf("handshake %+v; want one resend from %v, then established", h, n.clientAddr)
	}
}

// TestHandshakeFailedEvent: a client pinning another relay key sends INITs
// the relay cannot answer, and each is reported with its source.
func TestHandshakeFailedEvent(t *testing.T) {
	n := newNetwork(t, 92, defaultRelayConfig(), ClientConfig{RelayPublic: mustKey(7).Public})
	n.runFor(3 * time.Second)
	failed := 0
	for _, e := range n.relayEvents {
		if e, ok := e.(HandshakeFailed); ok {
			failed++
			if e.From != n.clientAddr || e.Err == nil {
				t.Errorf("failure %+v; want one from %v with an error", e, n.clientAddr)
			}
		}
	}
	if failed == 0 || uint64(failed) != n.relay.Stats().HandshakeFailures {
		t.Errorf("%d failure events, %d counted", failed, n.relay.Stats().HandshakeFailures)
	}
}
