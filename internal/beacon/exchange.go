// Package beacon exchanges a query for an answer over UDP, which is how a
// client reads a beacon when it has no other way out
// (spec/dns-lifeline.md §3.2 and §5.2).
//
// The exchange is deliberately small: one question, one answer, no retries
// inside it. §3.3's policy — how often to ask, which candidate to try, what
// a failure means — belongs to the caller, because those answers depend on
// session state this package does not have.
package beacon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/laneshetron/arc/internal/carrier/sockopt"
)

// ErrTruncated reports an answer with the TC bit set, which is §3.2's cue to
// retry with the EDNS(0) profile. It is not a failure, so it is its own
// error rather than a wrapped one.
var ErrTruncated = errors.New("beacon: answer truncated")

// ErrNoRecord reports a well-formed response that carried no TXT record
// owned by the queried name: a sinkhole, a wildcard, or a name with no
// record. §3.3 counts all of these as "no beacon this round", and they are
// distinct from an unreachable resolver because the exchange did complete.
var ErrNoRecord = errors.New("beacon: no record for the question")

// Exchanger sends queries to a resolver and reads the answers.
type Exchanger struct {
	// Resolver is the upstream to ask: a global-unicast IPv4 address, per
	// §5.2. A stub here would route the lifeline's own queries back into
	// the tunnel, which is the failure §5.2 exists to prevent, so callers
	// are expected to have validated it (tun.ValidateDNS).
	Resolver netip.Addr
	// Device is the physical interface to bind the socket to, per §5.2's
	// pin-the-socket rule. Empty leaves the socket unbound.
	Device string
	// Timeout bounds one query. Zero means DefaultTimeout.
	Timeout time.Duration
	// Port is the resolver's port. Zero means 53.
	Port uint16
}

// DefaultTimeout is the per-query deadline. §4.3 requires it to be at least
// one resolver round trip, and a resolver that has not answered in five
// seconds is not going to.
const DefaultTimeout = 5 * time.Second

// maxAnswer bounds what is read from the socket. It is the largest answer
// either profile can provoke — the EDNS cap is 846 (§3.2) — with room for a
// resolver that ignores the advertised buffer.
const maxAnswer = 4096

// Ask sends q and returns the parsed answer. A truncated answer returns the
// Response along with ErrTruncated, so the caller can see the TC bit without
// re-parsing the message.
func (e *Exchanger) Ask(ctx context.Context, q Query) (Response, error) {
	if !e.Resolver.IsValid() {
		return Response{}, errors.New("beacon: no resolver")
	}
	d := net.Dialer{
		Timeout: e.timeout(),
		// The socket is bound to the physical link, not merely addressed to
		// it: a resolver address that happens to be routable through the
		// tunnel must still be reached outside it (§5.2).
		Control: sockopt.Control(sockopt.Options{Device: e.Device}),
	}
	conn, err := d.DialContext(ctx, "udp", e.addr())
	if err != nil {
		return Response{}, fmt.Errorf("beacon: dial %s: %w", e.addr(), err)
	}
	defer conn.Close()
	// The deadline is the earlier of the per-query timeout and the
	// caller's context: SetDeadline takes no context, so a context that
	// expires mid-read would otherwise not be honoured. A watcher closes
	// the conn to unblock the read.
	deadline := time.Now().Add(e.timeout())
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return Response{}, fmt.Errorf("beacon: %w", err)
	}
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		select {
		case <-ctx.Done():
			conn.SetDeadline(time.Now())
		case <-stop:
		}
	}()
	if _, err := conn.Write(q.Wire); err != nil {
		return Response{}, fmt.Errorf("beacon: send: %w", err)
	}
	buf := make([]byte, maxAnswer)
	// noRecord remembers that the resolver answered us without a record for
	// our name, so the failure at the deadline is reported as what it was.
	noRecord := false
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return Response{}, fmt.Errorf("beacon: %w", ctxErr)
			}
			if noRecord {
				return Response{}, ErrNoRecord
			}
			return Response{}, fmt.Errorf("beacon: read: %w", err)
		}
		resp, err := ParseAnswer(q, buf[:n])
		// A datagram that is not a response to this question — a stale
		// answer, a spoofed one, or a resolver's own error message — is
		// dropped and the read continues until an answer matches. §3.1's
		// nonce is what makes "matches" mean something.
		if errors.Is(err, errForOther) || errors.Is(err, errNoQuestion) || errors.Is(err, errNotResponse) {
			continue
		}
		if err != nil {
			return resp, err
		}
		if resp.Truncated {
			return resp, ErrTruncated
		}
		if len(resp.Records) == 0 {
			// Our question, but no record for it: a sinkhole, a wildcard, or
			// a forgery echoing a nonce its sender could read off the wire.
			// Keep waiting for the real answer rather than ending the poll on
			// the first datagram, so one injected packet cannot deny a query
			// the resolver did answer. A genuine sinkhole never sends a
			// second, so it ends at the deadline as ErrNoRecord — and §3.3
			// backs off by minutes, which makes that wait irrelevant.
			noRecord = true
			continue
		}
		return resp, nil
	}
}

func (e *Exchanger) timeout() time.Duration {
	if e.Timeout > 0 {
		return e.Timeout
	}
	return DefaultTimeout
}

func (e *Exchanger) addr() string {
	port := e.Port
	if port == 0 {
		port = 53
	}
	return netip.AddrPortFrom(e.Resolver.Unmap(), port).String()
}

// Read asks the zone's beacon with both profiles in §3.2's order: bootstrap
// first, EDNS(0) only if the first answer was truncated. It returns the
// first record that parses, or an error describing the last failure.
//
// The record is *not* verified here; Decode does that, and §3.3 separates
// verification from transport so an unsigned record is reported differently
// from an unreachable resolver.
func (e *Exchanger) Read(ctx context.Context, zone string) (Response, error) {
	boot, err := NewQuery(zone, ProfileBootstrap, nil)
	if err != nil {
		return Response{}, err
	}
	resp, err := e.Ask(ctx, boot)
	if !errors.Is(err, ErrTruncated) {
		return resp, err
	}
	// Truncated: the record did not fit the 512-byte buffer, so ask again
	// with EDNS(0). §3.2 allows exactly one escalation — a resolver that
	// truncates the larger answer too has a record larger than the grammar
	// permits, which is not something another retry fixes.
	edns, err := NewQuery(zone, ProfileEDNS, nil)
	if err != nil {
		return Response{}, err
	}
	return e.Ask(ctx, edns)
}
