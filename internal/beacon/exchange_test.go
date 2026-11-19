package beacon

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// fakeResolver is an authoritative server bound to loopback: it answers
// whatever the test tells it to, and records what it was asked.
type fakeResolver struct {
	conn *net.UDPConn
	// handle builds the reply for one query. Returning nil sends nothing,
	// which is how a timeout is tested.
	handle func(t *testing.T, q Query, wire []byte) [][]byte

	mu    sync.Mutex
	asked []Query
	done  chan struct{}
}

func startResolver(t *testing.T, handle func(t *testing.T, q Query, wire []byte) [][]byte) *fakeResolver {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	r := &fakeResolver{conn: conn, handle: handle, done: make(chan struct{})}
	t.Cleanup(func() {
		close(r.done)
		conn.Close()
	})
	go func() {
		buf := make([]byte, 4096)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			wire := append([]byte(nil), buf[:n]...)
			q := parseQuestion(t, wire)
			r.mu.Lock()
			r.asked = append(r.asked, q)
			r.mu.Unlock()
			for _, reply := range r.handle(t, q, wire) {
				conn.WriteToUDP(reply, from)
			}
		}
	}()
	return r
}

// parseQuestion recovers the Query a message asks, so the handler can build
// an answer to it without the test plumbing the original through.
func parseQuestion(t *testing.T, wire []byte) Query {
	t.Helper()
	// NewQuery's output is a question; reuse the parser by treating the
	// query as its own template.
	return Query{Wire: wire, Name: questionName(t, wire)}
}

func (r *fakeResolver) addr(t *testing.T) (netip.Addr, uint16) {
	t.Helper()
	a := r.conn.LocalAddr().(*net.UDPAddr)
	addr, ok := netip.AddrFromSlice(a.IP)
	if !ok {
		t.Fatalf("bad address %s", a)
	}
	return addr.Unmap(), uint16(a.Port)
}

func (r *fakeResolver) exporter(t *testing.T) *Exchanger {
	t.Helper()
	addr, port := r.addr(t)
	return &Exchanger{Resolver: addr, Port: port, Timeout: 2 * time.Second}
}

func (r *fakeResolver) askCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.asked)
}

func TestAskReturnsTheRecord(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	pub, priv := testKey(t)
	content, err := Encode(oneRelay(t, now), Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	r := startResolver(t, func(t *testing.T, q Query, wire []byte) [][]byte {
		return [][]byte{replyTo(t, wire, content, false)}
	})
	resp, err := r.exporter(t).Read(context.Background(), testZone)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Records) != 1 {
		t.Fatalf("%d records", len(resp.Records))
	}
	b, err := Decode(resp.Records[0], Suffix(testZone), pub, now)
	if err != nil {
		t.Fatalf("record did not verify: %v", err)
	}
	if len(b.Relays) != 1 {
		t.Errorf("%d relays", len(b.Relays))
	}
	// §3.2: bootstrap first, and only bootstrap when it answers.
	if got := r.askCount(); got != 1 {
		t.Errorf("%d queries, want 1", got)
	}
}

func TestReadEscalatesToEDNSOnTruncation(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	pub, priv := testKey(t)
	content, err := Encode(oneRelay(t, now), Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	r := startResolver(t, func(t *testing.T, q Query, wire []byte) [][]byte {
		// The answer depends on whether the query carried an OPT record: a
		// resolver without EDNS(0) truncates, and the retry succeeds.
		if hasOPT(t, wire) {
			return [][]byte{replyTo(t, wire, content, false)}
		}
		return [][]byte{replyTo(t, wire, "", true)}
	})
	resp, err := r.exporter(t).Read(context.Background(), testZone)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Records) != 1 {
		t.Fatalf("%d records", len(resp.Records))
	}
	if _, err := Decode(resp.Records[0], Suffix(testZone), pub, now); err != nil {
		t.Fatal(err)
	}
	// Exactly two: bootstrap, then one escalation. §3.2 allows one.
	if got := r.askCount(); got != 2 {
		t.Errorf("%d queries, want 2", got)
	}
}

func TestReadDoesNotLoopOnPersistentTruncation(t *testing.T) {
	r := startResolver(t, func(t *testing.T, q Query, wire []byte) [][]byte {
		return [][]byte{replyTo(t, wire, "", true)}
	})
	_, err := r.exporter(t).Read(context.Background(), testZone)
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("got %v, want ErrTruncated", err)
	}
	if got := r.askCount(); got != 2 {
		t.Errorf("%d queries, want 2 (bootstrap then one escalation)", got)
	}
}

func TestAskDropsForeignResponses(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	pub, priv := testKey(t)
	content, err := Encode(oneRelay(t, now), Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	r := startResolver(t, func(t *testing.T, q Query, wire []byte) [][]byte {
		// A response to a different nonce, which is what a spoofed or
		// delayed answer from another poll looks like. §3.1's nonce rule
		// exists to make this detectable, so the client must drop it rather
		// than parse it.
		return [][]byte{
			replyToName(t, wire, "aaaaaaaaaaaaa._arcb.example.net.", content, false),
			replyTo(t, wire, content, false),
		}
	})
	resp, err := r.exporter(t).Ask(context.Background(), mustQuery(t, testZone, ProfileBootstrap))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Records) != 1 || resp.Records[0] != content {
		t.Fatalf("records %q", resp.Records)
	}
	if _, err := Decode(resp.Records[0], Suffix(testZone), pub, now); err != nil {
		t.Fatal(err)
	}
}

func TestAskTimesOut(t *testing.T) {
	r := startResolver(t, func(t *testing.T, q Query, wire []byte) [][]byte {
		return nil // a resolver that never answers
	})
	e := r.exporter(t)
	e.Timeout = 150 * time.Millisecond
	start := time.Now()
	_, err := e.Ask(context.Background(), mustQuery(t, testZone, ProfileBootstrap))
	if err == nil {
		t.Fatal("no error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("timed out after %s, want near %s", elapsed, e.Timeout)
	}
}

func TestAskRespectsContextCancellation(t *testing.T) {
	r := startResolver(t, func(t *testing.T, q Query, wire []byte) [][]byte { return nil })
	e := r.exporter(t)
	e.Timeout = 10 * time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := e.Ask(ctx, mustQuery(t, testZone, ProfileBootstrap)); err == nil {
		t.Fatal("no error")
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("took %s, want under 3s", elapsed)
	}
}

func TestAskWithoutResolver(t *testing.T) {
	e := &Exchanger{}
	if _, err := e.Ask(context.Background(), mustQuery(t, testZone, ProfileBootstrap)); err == nil {
		t.Fatal("no error")
	}
}

func TestAskIgnoresARecordlessAnswerAndWaitsForTheRealOne(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	pub, priv := testKey(t)
	content, err := Encode(oneRelay(t, now), Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	r := startResolver(t, func(t *testing.T, q Query, wire []byte) [][]byte {
		// A forgery that read our nonce off the wire and echoed it with no
		// record, followed by the resolver's real answer. Ending the poll on
		// the first datagram would let any on-path attacker deny every query
		// by answering it first.
		return [][]byte{replyTo(t, wire, "", false), replyTo(t, wire, content, false)}
	})
	resp, err := r.exporter(t).Ask(context.Background(), mustQuery(t, testZone, ProfileBootstrap))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Records) != 1 {
		t.Fatalf("%d records", len(resp.Records))
	}
	if _, err := Decode(resp.Records[0], Suffix(testZone), pub, now); err != nil {
		t.Fatal(err)
	}
}

func TestAskReportsARecordlessAnswer(t *testing.T) {
	r := startResolver(t, func(t *testing.T, q Query, wire []byte) [][]byte {
		// A sinkhole: the right question, no TXT for it, and no second
		// datagram ever.
		return [][]byte{replyTo(t, wire, "", false)}
	})
	e := r.exporter(t)
	e.Timeout = 150 * time.Millisecond
	_, err := e.Ask(context.Background(), mustQuery(t, testZone, ProfileBootstrap))
	if !errors.Is(err, ErrNoRecord) {
		t.Fatalf("got %v, want ErrNoRecord", err)
	}
}
