package session

import (
	"bytes"
	"errors"
	"io"
	"math/rand/v2"
	"net/netip"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

var tcpDst = netip.MustParseAddrPort("198.51.100.7:443")

// streamEnd is one end of a stream in a test: what it sends and what it
// has received.
type streamEnd struct {
	send     []byte
	sent     int
	closed   bool // FIN queued
	got      []byte
	eof      bool
	eofAt    time.Time
	err      error
	maxBufed int // most bytes received and not yet read, if reading is paused
}

// streamPair drives one stream's two ends through a network.
type streamPair struct {
	n             *network
	s             *RelaySession
	id            uint32
	client, relay streamEnd
	relayReads    bool // the relay reads what arrives
	relayOpen     bool // the relay has reported the stream
}

// openPair opens a stream from the client and waits for the relay's
// StreamOpened.
func openPair(t *testing.T, n *network, s *RelaySession, up, down []byte) *streamPair {
	t.Helper()
	id, err := n.client.OpenStream(n.now, tcpDst)
	if err != nil {
		t.Fatal(err)
	}
	sp := &streamPair{n: n, s: s, id: id, relayReads: true}
	sp.client.send, sp.relay.send = up, down
	if !n.runUntil(10*time.Second, func() bool { sp.pump(); return sp.opened() }) {
		t.Fatal("relay never reported the stream")
	}
	return sp
}

func (sp *streamPair) opened() bool {
	if sp.relayOpen {
		return true
	}
	for _, e := range sp.n.relayEvents {
		if e, ok := e.(StreamOpened); ok && e.ID == sp.id {
			if e.Dst != tcpDst {
				sp.n.t.Fatalf("opened to %v, want %v", e.Dst, tcpDst)
			}
			sp.relayOpen = true
		}
	}
	return sp.relayOpen
}

// pump writes and reads what each end can.
func (sp *streamPair) pump() {
	now := sp.n.now
	ends := []struct {
		e     *streamEnd
		write func([]byte) (int, error)
		read  func([]byte) (int, error)
		close func() error
		reads bool
	}{
		{&sp.client, func(p []byte) (int, error) { return sp.n.client.StreamWrite(now, sp.id, p) },
			func(p []byte) (int, error) { return sp.n.client.StreamRead(now, sp.id, p) },
			func() error { return sp.n.client.StreamCloseWrite(now, sp.id) }, true},
		{&sp.relay, func(p []byte) (int, error) { return sp.s.StreamWrite(now, sp.id, p) },
			func(p []byte) (int, error) { return sp.s.StreamRead(now, sp.id, p) },
			func() error { return sp.s.StreamCloseWrite(now, sp.id) }, sp.relayReads},
	}
	var buf [32 << 10]byte
	for i, x := range ends {
		e := x.e
		if e.err != nil || i == 1 && !sp.opened() {
			continue
		}
		for e.sent < len(e.send) {
			k, err := x.write(e.send[e.sent:])
			if err != nil {
				e.err = err
				break
			}
			if k == 0 {
				break
			}
			e.sent += k
		}
		if e.sent == len(e.send) && !e.closed && e.err == nil {
			if err := x.close(); err != nil {
				e.err = err
			}
			e.closed = true
		}
		for x.reads && !e.eof && e.err == nil {
			k, err := x.read(buf[:])
			e.got = append(e.got, buf[:k]...)
			if err == io.EOF {
				e.eof, e.eofAt = true, now
			} else if err != nil {
				e.err = err
			}
			if k == 0 {
				break
			}
		}
	}
	sp.n.pump()
}

// run drives the pair until both ends have everything or the simulated
// limit passes, and reports whether they finished.
func (sp *streamPair) run(limit time.Duration) bool {
	return sp.n.runUntil(limit, func() bool {
		sp.pump()
		return (sp.client.eof && sp.relay.eof) || sp.client.err != nil || sp.relay.err != nil
	})
}

func randomBytes(seed uint64, n int) []byte {
	b := make([]byte, n)
	r := rand.New(rand.NewPCG(seed, 1))
	for i := range b {
		b[i] = byte(r.Uint32())
	}
	return b
}

func streamNetwork(t *testing.T, seed uint64) (*network, *RelaySession) {
	t.Helper()
	n := newNetwork(t, seed, defaultRelayConfig(), ClientConfig{})
	s := n.establish()
	n.runFor(time.Second) // MTU probes complete
	return n, s
}

func TestStreamTransfer(t *testing.T) {
	n, s := streamNetwork(t, 60)
	up, down := randomBytes(1, 300_000), randomBytes(2, 1_000_000)
	sp := openPair(t, n, s, up, down)
	if !sp.run(30 * time.Second) {
		t.Fatalf("transfer incomplete: client got %d/%d, relay %d/%d (errors %v, %v)",
			len(sp.client.got), len(down), len(sp.relay.got), len(up), sp.client.err, sp.relay.err)
	}
	if !bytes.Equal(sp.relay.got, up) || !bytes.Equal(sp.client.got, down) {
		t.Fatal("stream bytes corrupted")
	}
	// Both ends finished both directions: the stream goes away.
	n.runFor(time.Second)
	if info := n.client.StreamInfo(sp.id); !info.Done || info.Err != nil {
		t.Errorf("client stream info %+v, want done", info)
	}
	if info := s.StreamInfo(sp.id); !info.Done || info.Err != nil {
		t.Errorf("relay stream info %+v, want done", info)
	}
	if len(n.client.conn.streams.streams) != 0 || len(s.conn.streams.streams) != 0 {
		t.Errorf("%d client and %d relay streams left", len(n.client.conn.streams.streams), len(s.conn.streams.streams))
	}
	if st := n.client.Stats(); st.StreamBytesRetransmitted != 0 {
		t.Errorf("%d bytes retransmitted on a clean link", st.StreamBytesRetransmitted)
	}
}

func TestStreamReset(t *testing.T) {
	n, s := streamNetwork(t, 61)
	sp := openPair(t, n, s, randomBytes(1, 100_000), nil)
	// The relay could not connect.
	s.StreamReset(n.now, sp.id, wire.CodeConnectFailed)
	sp.relay.err = ErrStreamClosed // the relay is done with it
	n.runUntil(5*time.Second, func() bool { sp.pump(); return sp.client.err != nil })
	var rerr *StreamResetError
	if !errors.As(sp.client.err, &rerr) || rerr.Code != wire.CodeConnectFailed {
		t.Fatalf("client error %v, want a reset with CONNECT_FAILED", sp.client.err)
	}
	if info := n.client.StreamInfo(sp.id); !info.Done {
		t.Errorf("client stream info %+v", info)
	}
	n.runFor(2 * time.Second)
	cs, rs := &n.client.conn.streams, &s.conn.streams
	if len(cs.streams) != 0 || len(rs.streams) != 0 {
		t.Errorf("%d client and %d relay streams left", len(cs.streams), len(rs.streams))
	}
	// Each end counted the other's final size, so connection credit
	// lines up.
	if cs.sendUsed != rs.recvHigh || rs.sendUsed != cs.recvHigh || rs.recvTaken != rs.recvHigh {
		t.Errorf("flow control: client sent %d, relay counted %d (taken %d); relay sent %d, client counted %d",
			cs.sendUsed, rs.recvHigh, rs.recvTaken, rs.sendUsed, cs.recvHigh)
	}
	// Streams opened later work.
	sp2 := openPair(t, n, s, []byte("hello"), []byte("world"))
	if !sp2.run(5*time.Second) || string(sp2.relay.got) != "hello" || string(sp2.client.got) != "world" {
		t.Fatalf("second stream: relay got %q, client %q", sp2.relay.got, sp2.client.got)
	}
}

func TestStreamFlowControl(t *testing.T) {
	n, s := streamNetwork(t, 62)
	up := randomBytes(3, 3*streamWindow)
	sp := openPair(t, n, s, up, nil)
	sp.relayReads = false
	n.runUntil(10*time.Second, func() bool { sp.pump(); return false })
	r := s.conn.streams.streams[sp.id]
	buffered := len(r.recv.data)
	for _, sg := range r.recv.segs {
		buffered += len(sg.data)
	}
	if buffered > streamWindow || r.recv.high > streamWindow {
		t.Fatalf("relay buffers %d bytes (high %d) of an unread stream; window %d", buffered, r.recv.high, streamWindow)
	}
	if buffered < streamWindow/2 {
		t.Fatalf("only %d bytes arrived while the relay was not reading", buffered)
	}
	sp.relayReads = true
	if !sp.run(30*time.Second) || !bytes.Equal(sp.relay.got, up) {
		t.Fatalf("relay got %d/%d bytes after resuming", len(sp.relay.got), len(up))
	}
}

func TestStreamsUnsupported(t *testing.T) {
	rc := defaultRelayConfig()
	rc.NoStreams = true
	n := newNetwork(t, 63, rc, ClientConfig{})
	n.establish()
	if _, err := n.client.OpenStream(n.now, tcpDst); !errors.Is(err, ErrStreamsUnsupported) {
		t.Fatalf("OpenStream: %v", err)
	}
}

// TestStreamLoss measures stream goodput on a 10 Mbit/s link with a 40 ms
// RTT under uniform loss in both directions, with loss before the link (as
// netem on egress) and after it (as on a lossy radio hop, where lost
// packets cost capacity too).
func TestStreamLoss(t *testing.T) {
	const rate = 1_250_000 // bytes per second
	for _, tc := range []struct {
		loss    float64
		size    int
		atLeast float64 // goodput as a fraction of rate*(1-loss)
	}{
		{0, 4 << 20, 0.8},
		{0.1, 2 << 20, 0.6},
		{0.5, 1 << 20, 0.4},
		{0.9, 256 << 10, 0.1},
	} {
		for _, after := range []bool{false, true} {
			if after && tc.loss == 0 {
				continue
			}
			where := "before"
			if after {
				where = "after"
			}
			n, s := streamNetwork(t, 64)
			for _, l := range []*link{n.up, n.down} {
				l.rate, l.loss, l.lossAfterQueue = rate, tc.loss, after
			}
			down := randomBytes(5, tc.size)
			start := n.now
			sp := openPair(t, n, s, []byte("GET"), down)
			if !sp.run(120 * time.Second) {
				t.Errorf("loss %.0f%% %s: incomplete after 120 s: %d/%d bytes (errors %v, %v)",
					tc.loss*100, where, len(sp.client.got), tc.size, sp.client.err, sp.relay.err)
				continue
			}
			if !bytes.Equal(sp.client.got, down) {
				t.Fatalf("loss %.0f%%: corrupted", tc.loss*100)
			}
			secs := sp.client.eofAt.Sub(start).Seconds()
			goodput := float64(tc.size) / secs
			st := s.Stats()
			t.Logf("loss %.0f%% %s the link: %d KiB in %.1f s: %.0f kbit/s (%.0f%% of the link's share); sent %.1fx the data (%.1fx retransmitted, %.1fx repeats)",
				tc.loss*100, where, tc.size>>10, secs, goodput*8/1000, 100*goodput/(rate*(1-tc.loss)),
				float64(st.StreamBytesSent)/float64(tc.size), float64(st.StreamBytesRetransmitted)/float64(tc.size),
				float64(st.StreamBytesRepeated)/float64(tc.size))
			if goodput < tc.atLeast*rate*(1-tc.loss) {
				t.Errorf("loss %.0f%% %s: goodput %.0f kbit/s, want at least %.0f%% of %.0f kbit/s",
					tc.loss*100, where, goodput*8/1000, tc.atLeast*100, rate*(1-tc.loss)*8/1000)
			}
		}
	}
}

// runPairs drives several streams until all finish or the limit passes.
func runPairs(n *network, pairs []*streamPair, limit time.Duration) bool {
	return n.runUntil(limit, func() bool {
		done := true
		for _, sp := range pairs {
			sp.pump()
			done = done && sp.client.eof && sp.relay.eof
		}
		return done
	})
}

func TestStreamQueueBounded(t *testing.T) {
	// A deep buffer (300 ms at 10 Mbit/s) lets loss-based TCP build a
	// standing queue; stream rate control keeps it near queueTarget.
	n, s := streamNetwork(t, 65)
	for _, l := range []*link{n.up, n.down} {
		l.rate, l.queue = 1_250_000, 300*time.Millisecond
	}
	down := randomBytes(6, 8<<20)
	sp := openPair(t, n, s, nil, down)
	var queued time.Duration
	samples := 0
	start := n.now
	next := n.now
	ok := n.runUntil(60*time.Second, func() bool {
		sp.pump()
		if p := s.conn.paths[0]; n.now.Sub(start) > 2*time.Second && !n.now.Before(next) {
			queued += p.rtt.latest - p.rtt.minRTT()
			samples++
			next = n.now.Add(10 * time.Millisecond)
		}
		return sp.client.eof
	})
	if !ok || !bytes.Equal(sp.client.got, down) {
		t.Fatalf("transfer incomplete: %d/%d", len(sp.client.got), len(down))
	}
	secs := sp.client.eofAt.Sub(start).Seconds()
	mean := queued / time.Duration(samples)
	t.Logf("%.1f s, %.0f%% of the link; mean queueing delay %v", secs, 100*float64(len(down))/secs/1_250_000, mean)
	if mean > 25*time.Millisecond {
		t.Errorf("mean queueing delay %v; want at most 25 ms", mean)
	}
	if float64(len(down))/secs < 0.8*1_250_000 {
		t.Errorf("goodput %.0f B/s; want at least 80%% of the link", float64(len(down))/secs)
	}
}

func TestStreamsShare(t *testing.T) {
	n, s := streamNetwork(t, 66)
	for _, l := range []*link{n.up, n.down} {
		l.rate = 1_250_000
	}
	var pairs []*streamPair
	for i := range 4 {
		pairs = append(pairs, openPair(t, n, s, nil, randomBytes(uint64(10+i), 1<<20)))
	}
	start := n.now
	if !runPairs(n, pairs, 30*time.Second) {
		t.Fatal("transfers incomplete")
	}
	var first, last time.Duration
	for i, sp := range pairs {
		if !bytes.Equal(sp.client.got, sp.relay.send) {
			t.Fatalf("stream %d corrupted", i)
		}
		d := sp.client.eofAt.Sub(start)
		if i == 0 || d < first {
			first = d
		}
		last = max(last, d)
	}
	t.Logf("4 x 1 MiB: first done after %v, last after %v", first, last)
	if last > 2*first {
		t.Errorf("first stream done after %v, last after %v; want them sharing the link", first, last)
	}
}

func TestStreamSurvivesOutage(t *testing.T) {
	n, s := streamNetwork(t, 67)
	for _, l := range []*link{n.up, n.down} {
		l.rate = 1_250_000
	}
	down := randomBytes(7, 4<<20)
	sp := openPair(t, n, s, nil, down)
	n.runUntil(10*time.Second, func() bool { sp.pump(); return len(sp.client.got) > 1<<20 })
	n.up.down, n.down.down = true, true
	n.runUntil(5*time.Second, func() bool { sp.pump(); return false })
	n.up.down, n.down.down = false, false
	resumed := n.now
	if !sp.run(30*time.Second) || !bytes.Equal(sp.client.got, down) {
		t.Fatalf("transfer incomplete after the outage: %d/%d", len(sp.client.got), len(down))
	}
	// About 3 MiB remained: 2.5 s at the link rate.
	if d := sp.client.eofAt.Sub(resumed); d > 6*time.Second {
		t.Errorf("took %v after the outage ended", d)
	}
}

func TestStreamMovesToAnotherPath(t *testing.T) {
	n, s, _, _ := establishTwoPaths(t, 68, 20*time.Millisecond)
	down := randomBytes(8, 4<<20)
	sp := openPair(t, n, s, []byte("GET"), down)
	n.runUntil(10*time.Second, func() bool { sp.pump(); return len(sp.client.got) > 1<<20 })
	n.up.down, n.down.down = true, true // path 0 fails for good
	if !sp.run(30*time.Second) || !bytes.Equal(sp.client.got, down) {
		t.Fatalf("transfer incomplete after path 0 failed: %d/%d", len(sp.client.got), len(down))
	}
}

func TestStreamReassembly(t *testing.T) {
	c := &conn{}
	c.streams.init(false)
	s := c.streams.newStream(1, tcpDst)
	data := randomBytes(9, 100)
	// Overlapping pieces out of order, as retransmissions and repeats with
	// different frame boundaries produce.
	for _, r := range [][2]int{{50, 70}, {60, 90}, {80, 100}, {55, 65}, {20, 40}, {30, 60}, {10, 20}, {0, 15}} {
		c.insert(s, uint64(r[0]), data[r[0]:r[1]])
		held := len(s.recv.data)
		for i, sg := range s.recv.segs {
			held += len(sg.data)
			if i > 0 && s.recv.segs[i-1].off+uint64(len(s.recv.segs[i-1].data)) > sg.off {
				t.Fatalf("after %v: segments overlap: %+v", r, s.recv.segs)
			}
		}
		if held > 100 {
			t.Fatalf("after %v: %d bytes held for 100", r, held)
		}
	}
	if !bytes.Equal(s.recv.data, data) || len(s.recv.segs) != 0 {
		t.Fatalf("reassembled %d bytes (%d segments left)", len(s.recv.data), len(s.recv.segs))
	}
}

func TestStreamRTTRise(t *testing.T) {
	// The link's delay rises from 10 to 50 ms each way, as when a network
	// change adds latency: the path's minimum RTT remembers the old delay
	// for a minute, and rate control must not take the difference for a
	// queue and hold at its floor. The comparison is the same transfer on
	// a link that had the higher delay all along.
	transfer := func(rise bool) float64 {
		n, s := streamNetwork(t, 69)
		for _, l := range []*link{n.up, n.down} {
			l.rate = 1_250_000
			if !rise {
				l.delay = 50 * time.Millisecond
			}
		}
		sp := openPair(t, n, s, nil, randomBytes(9, 1<<20))
		if !sp.run(30 * time.Second) {
			t.Fatal("first transfer incomplete")
		}
		n.up.delay, n.down.delay = 50*time.Millisecond, 50*time.Millisecond
		n.runFor(time.Second)
		down := randomBytes(10, 4<<20)
		start := n.now
		sp = openPair(t, n, s, nil, down)
		if !sp.run(60*time.Second) || !bytes.Equal(sp.client.got, down) {
			t.Fatalf("transfer incomplete: %d/%d", len(sp.client.got), len(down))
		}
		return sp.client.eofAt.Sub(start).Seconds()
	}
	risen, steady := transfer(true), transfer(false)
	t.Logf("4 MiB at 100 ms RTT: %.1f s after the RTT rose, %.1f s on a link that always had it", risen, steady)
	if risen > 1.5*steady {
		t.Errorf("%.1f s after the RTT rose, against %.1f s; want at most 1.5x", risen, steady)
	}
}

func TestStreamLossAfterRTTRise(t *testing.T) {
	// As in test/netns/split.sh, the link turns slower and lossy (40 ms
	// RTT, 5% loss each way, uniform or in bursts of 10) a second before a
	// transfer on a 50 Mbit/s link. Rate control first takes the higher
	// RTT for a queue; once it adopts the new base it must find the rate
	// again, not creep up from where the false backoffs left it.
	for _, burst := range []float64{1, 10} {
		n, s := streamNetwork(t, 91)
		for _, l := range []*link{n.up, n.down} {
			l.rate, l.delay = 6_250_000, 20*time.Millisecond
			if burst == 1 {
				l.loss = 0.05
			} else {
				l.bursty(0.05, burst)
			}
		}
		n.runFor(time.Second)
		data := randomBytes(11, 16<<20)
		start := n.now
		sp := openPair(t, n, s, nil, data)
		if !sp.run(60*time.Second) || !bytes.Equal(sp.client.got, data) {
			t.Fatalf("burst %v: transfer incomplete: %d/%d", burst, len(sp.client.got), len(data))
		}
		goodput := float64(len(data)) / sp.client.eofAt.Sub(start).Seconds()
		t.Logf("mean burst %v: 16 MiB at %.1f Mbit/s", burst, goodput*8/1e6)
		if goodput < 0.5*6_250_000 {
			t.Errorf("mean burst %v: goodput %.1f Mbit/s; want at least half the 50 Mbit/s link", burst, goodput*8/1e6)
		}
	}
}

func TestStreamBurstyLoss(t *testing.T) {
	// 5% loss in bursts of 10 each way on a 50 Mbit/s link with a steady
	// 40 ms RTT.
	n := newNetwork(t, 91, defaultRelayConfig(), ClientConfig{})
	n.up.delay, n.down.delay = 20*time.Millisecond, 20*time.Millisecond
	s := n.establish()
	n.runFor(time.Second)
	for _, l := range []*link{n.up, n.down} {
		l.rate = 6_250_000
		l.bursty(0.05, 10)
	}
	data := randomBytes(11, 16<<20)
	start := n.now
	sp := openPair(t, n, s, nil, data)
	if !sp.run(60*time.Second) || !bytes.Equal(sp.client.got, data) {
		t.Fatalf("transfer incomplete: %d/%d", len(sp.client.got), len(data))
	}
	goodput := float64(len(data)) / sp.client.eofAt.Sub(start).Seconds()
	t.Logf("16 MiB at %.1f Mbit/s", goodput*8/1e6)
	if goodput < 0.5*6_250_000 {
		t.Errorf("goodput %.1f Mbit/s; want at least half the 50 Mbit/s link", goodput*8/1e6)
	}
}

func TestStreamDelayVariance(t *testing.T) {
	// Wi-Fi varies the delay of packets it keeps in order by several to
	// tens of milliseconds. Rate control must not take that for a queue:
	// over a 50 Mbit/s link at 40 ms RTT whose delay also varies by up to
	// 20 ms each way, a transfer reached 9.3 Mbit/s when every round whose
	// lowest sample beat the target counted as a queue (and 44 without the
	// variance).
	transfer := func(wobble time.Duration) float64 {
		// The link is set before the session starts, so that its minimum
		// RTT is the link's (TestStreamRTTRise covers a change).
		n := newNetwork(t, 93, defaultRelayConfig(), ClientConfig{})
		for _, l := range []*link{n.up, n.down} {
			l.rate, l.delay, l.wobble = 6_250_000, 20*time.Millisecond, wobble
		}
		s := n.establish()
		n.runFor(time.Second)
		data := randomBytes(12, 16<<20)
		start := n.now
		sp := openPair(t, n, s, nil, data)
		if !sp.run(60*time.Second) || !bytes.Equal(sp.client.got, data) {
			t.Fatalf("wobble %v: transfer incomplete: %d/%d", wobble, len(sp.client.got), len(data))
		}
		return float64(len(data)) / sp.client.eofAt.Sub(start).Seconds()
	}
	steady, varied := transfer(0), transfer(20*time.Millisecond)
	t.Logf("16 MiB at 40 ms RTT: %.1f Mbit/s steady, %.1f Mbit/s with delay varying by up to 20 ms", steady*8/1e6, varied*8/1e6)
	if varied < 0.4*6_250_000 {
		t.Errorf("goodput %.1f Mbit/s with delay variance; want at least 40%% of the 50 Mbit/s link", varied*8/1e6)
	}
}

func TestStreamStalls(t *testing.T) {
	// Wi-Fi that leaves the channel (a Mac's AWDL) stops the link for 90
	// ms every 455 ms; what is sent meanwhile is lost. Rate control must
	// retransmit without backing off for each stall: the link's capacity
	// is unchanged, and ~80% of the time it carries data. 50 Mbit/s at
	// 40 ms RTT. Backing off at every stall, rate control managed 5.0
	// Mbit/s. (A whole window is lost to each stall here, unlike behind an
	// access point that holds some frames, so the bar is modest.)
	n := newNetwork(t, 95, defaultRelayConfig(), ClientConfig{})
	for _, l := range []*link{n.up, n.down} {
		l.rate, l.delay = 6_250_000, 20*time.Millisecond
	}
	s := n.establish()
	n.runFor(time.Second)
	data := randomBytes(13, 16<<20)
	start := n.now
	sp := openPair(t, n, s, nil, data)
	ok := n.runUntil(60*time.Second, func() bool {
		sp.pump()
		down := n.now.Sub(start)%(455*time.Millisecond) < 90*time.Millisecond
		n.up.down, n.down.down = down, down
		return sp.client.eof
	})
	n.up.down, n.down.down = false, false
	if !ok || !bytes.Equal(sp.client.got, data) {
		t.Fatalf("transfer incomplete: %d/%d", len(sp.client.got), len(data))
	}
	goodput := float64(len(data)) / sp.client.eofAt.Sub(start).Seconds()
	t.Logf("16 MiB through stalls at %.1f Mbit/s (%d stalls seen)", goodput*8/1e6, s.conn.paths[0].cc.stalls)
	if goodput < 0.25*6_250_000 {
		t.Errorf("goodput %.1f Mbit/s through stalls; want at least a quarter of the 50 Mbit/s link", goodput*8/1e6)
	}
}

func TestStreamLongRTTNotStalls(t *testing.T) {
	// Acknowledgements arriving regularly 30 ms or more apart, as on a
	// long path with few packets in flight early on, are its normal
	// cadence, not stalls. Taking them for stalls held the rate: 1 MiB
	// over a clean 50 Mbit/s link with 200 ms delay each way took 17 s,
	// against 3 s before stall detection.
	n := newNetwork(t, 99, defaultRelayConfig(), ClientConfig{})
	for _, l := range []*link{n.up, n.down} {
		l.rate, l.delay = 6_250_000, 200*time.Millisecond
	}
	s := n.establish()
	n.runFor(2 * time.Second)
	data := randomBytes(16, 1<<20)
	start := n.now
	sp := openPair(t, n, s, nil, data)
	if !sp.run(60*time.Second) || !bytes.Equal(sp.client.got, data) {
		t.Fatalf("transfer incomplete: %d/%d", len(sp.client.got), len(data))
	}
	took := sp.client.eofAt.Sub(start)
	t.Logf("1 MiB at 400 ms RTT in %v (%d stalls seen)", took.Round(10*time.Millisecond), s.conn.paths[0].cc.stalls)
	if took > 5*time.Second {
		t.Errorf("1 MiB at 400 ms RTT took %v; want at most 5 s", took)
	}
}

// TestStreamCongestionWithAckBlackouts checks that stall detection does
// not hide congestion. A link whose acknowledgements stop for 60 ms every
// 400 ms (longer than the base RTT, so each blackout counts as a stall)
// while the data direction keeps flowing, through a congested 10 Mbit/s
// bottleneck: the rate must still converge, keeping the bottleneck's
// queue short when it is deep and its drops few when it is shallow,
// rather than suppressing every backoff near a stall.
func TestStreamCongestionWithAckBlackouts(t *testing.T) {
	const rate = 1_250_000
	type result struct {
		goodput float64       // fraction of the link
		queued  time.Duration // mean queueing delay at the bottleneck
		dropped float64       // fraction of datagrams the bottleneck dropped
		stalls  int
	}
	run := func(queue time.Duration, blackouts bool) result {
		n := newNetwork(t, 97, defaultRelayConfig(), ClientConfig{})
		for _, l := range []*link{n.up, n.down} {
			l.rate, l.delay = rate, 20*time.Millisecond
		}
		n.down.queue = queue
		s := n.establish()
		n.runFor(time.Second)
		data := randomBytes(17, 8<<20)
		start := n.now
		sp := openPair(t, n, s, nil, data)
		sent0, drops0 := n.down.sent, n.down.drops
		var queued time.Duration
		samples := 0
		next := n.now
		ok := n.runUntil(60*time.Second, func() bool {
			sp.pump()
			if blackouts {
				n.up.down = n.now.Sub(start)%(400*time.Millisecond) < 60*time.Millisecond
			}
			if n.now.Sub(start) > 2*time.Second && !n.now.Before(next) {
				queued += max(n.down.busyUntil.Sub(n.now), 0)
				samples++
				next = n.now.Add(10 * time.Millisecond)
			}
			return sp.client.eof
		})
		n.up.down = false
		if !ok || !bytes.Equal(sp.client.got, data) {
			t.Fatalf("queue %v, blackouts %v: transfer incomplete: %d/%d", queue, blackouts, len(sp.client.got), len(data))
		}
		return result{
			goodput: float64(len(data)) / sp.client.eofAt.Sub(start).Seconds() / rate,
			queued:  queued / time.Duration(max(samples, 1)),
			dropped: float64(n.down.drops-drops0) / float64(max(n.down.sent-sent0, 1)),
			stalls:  s.conn.paths[0].cc.stalls,
		}
	}
	for _, queue := range []time.Duration{300 * time.Millisecond, 30 * time.Millisecond} {
		base, got := run(queue, false), run(queue, true)
		for _, r := range []struct {
			name string
			r    result
		}{{"steady", base}, {"ack blackouts", got}} {
			t.Logf("%v queue, %s: %.0f%% of the link, mean queueing delay %v, %.2f%% dropped, %d stalls",
				queue, r.name, 100*r.r.goodput, r.r.queued.Round(100*time.Microsecond), 100*r.r.dropped, r.r.stalls)
		}
		if got.stalls == 0 {
			t.Errorf("%v queue: no blackout counted as a stall; the test exercises nothing", queue)
		}
		if got.goodput < 0.7 {
			t.Errorf("%v queue: %.0f%% of the link with ack blackouts; want at least 70%%", queue, 100*got.goodput)
		}
		// A stall excuses delay up to its own length (60 ms here) beyond
		// the target, so a deep queue settles near 100 ms; ignoring delay
		// around stalls altogether left the 300 ms queue full (245 ms
		// mean, 17% dropped).
		if got.queued > queue/2 {
			t.Errorf("%v queue: mean queueing delay %v with ack blackouts; want at most half the queue", queue, got.queued)
		}
		if got.dropped > base.dropped+0.03 {
			t.Errorf("%v queue: %.1f%% dropped with ack blackouts, %.1f%% without; want at most 3 points more",
				queue, 100*got.dropped, 100*base.dropped)
		}
	}
}
