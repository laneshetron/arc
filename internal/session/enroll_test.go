package session

import (
	"errors"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

// TestPendingAuthAndEnrolled: an Authorizer still deciding leaves AUTH
// unanswered; the client's repeats get the answer once it has decided,
// with ENROLLED, under heavy loss both ways.
func TestPendingAuthAndEnrolled(t *testing.T) {
	calls := 0
	enrolled := &wire.Enrolled{DeviceID: [8]byte{1, 2, 3, 4, 5, 6, 7, 8}, Name: "laptop"}
	rc := defaultRelayConfig()
	rc.Authorize = func(c, k []byte, prior *wire.AuthResult) (Authorization, error) {
		calls++
		if calls < 3 {
			return Authorization{}, ErrAuthPending
		}
		a, err := testAuthorizer(c, k, prior)
		a.Enrolled = enrolled
		return a, err
	}
	n := newNetwork(t, 401, rc, ClientConfig{})
	n.up.loss, n.down.loss = 0.5, 0.5
	s := n.establish()
	if !n.runUntil(30*time.Second, func() bool {
		for _, e := range n.clientEvents {
			if e, ok := e.(Enrolled); ok && e.DeviceID == enrolled.DeviceID && e.Name == "laptop" {
				return true
			}
		}
		return false
	}) {
		t.Fatal("no Enrolled event")
	}
	if s.Enrolled() == nil || calls < 3 {
		t.Errorf("relay session enrolled %v after %d calls", s.Enrolled(), calls)
	}
	count := 0
	for _, e := range n.clientEvents {
		if _, ok := e.(Enrolled); ok {
			count++
		}
	}
	if count != 1 {
		t.Errorf("%d Enrolled events", count)
	}
}

// TestInviteRefusals: an AuthError's code reaches the client as its
// error, which is an authentication failure.
func TestInviteRefusals(t *testing.T) {
	for _, tc := range []struct {
		code wire.ErrorCode
		want error
	}{{wire.CodeInviteUsed, ErrInviteUsed}, {wire.CodeInviteExpired, ErrInviteExpired}} {
		rc := defaultRelayConfig()
		rc.Authorize = func([]byte, []byte, *wire.AuthResult) (Authorization, error) {
			return Authorization{}, &AuthError{Code: tc.code, Err: errors.New("refused")}
		}
		n := newNetwork(t, 402, rc, ClientConfig{})
		if !n.runUntil(30*time.Second, func() bool { return n.client.State() == StateClosed }) {
			t.Fatalf("code %d: client not closed", tc.code)
		}
		if err := n.clientClosed(); !errors.Is(err, tc.want) || !errors.Is(err, ErrAuthFailed) {
			t.Errorf("code %d: client closed with %v", tc.code, err)
		}
	}
}
