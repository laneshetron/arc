package session

import (
	"encoding/binary"
	"errors"
	"math/rand/v2"
	"net/netip"
	"sort"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/wire"
)

// link impairments, applied independently per datagram and direction.
type link struct {
	loss   float64
	dup    float64
	delay  time.Duration
	jitter time.Duration // uniform extra delay; reorders packets
	down   bool          // drop everything
}

type delivery struct {
	at      time.Time
	seq     int
	toRelay bool
	data    []byte
}

// network connects one client and one relay over an impaired link, driven
// by a fake clock.
type network struct {
	t          *testing.T
	now        time.Time
	rng        *rand.Rand
	up, down   link // client→relay, relay→client
	inflight   []delivery
	seq        int
	client     *Client
	relay      *Relay
	clientAddr netip.AddrPort

	clientEvents []ClientEvent
	relayEvents  []RelayEvent
	tap          func(toRelay bool, data []byte) // observes every sent datagram
}

var (
	relayKey  = mustKey(1)
	clientKey = mustKey(2)
	lease     = [4]byte{10, 77, 0, 2}
)

func mustKey(seed byte) crypto.StaticKey {
	k, err := crypto.GenerateStaticKey(rand.NewChaCha8([32]byte{seed}))
	if err != nil {
		panic(err)
	}
	return k
}

func testAuthorizer(credential, _ []byte) (wire.AuthResult, error) {
	if string(credential) != "good" {
		return wire.AuthResult{}, errors.New("bad credential")
	}
	return wire.AuthResult{IPv4: lease, Prefix4: 16, TunMTU: 1280, DNSv4: [4]byte{10, 77, 0, 1}}, nil
}

func defaultRelayConfig() RelayConfig {
	return RelayConfig{Static: relayKey, ResetSecret: [32]byte{9}, Authorize: testAuthorizer}
}

func newNetwork(t *testing.T, seed uint64, rc RelayConfig, cc ClientConfig) *network {
	t.Helper()
	n := &network{
		t:          t,
		now:        time.Unix(1_000_000, 0),
		rng:        rand.New(rand.NewPCG(seed, seed^0x5eed)),
		clientAddr: netip.MustParseAddrPort("192.0.2.10:40000"),
	}
	n.up.delay, n.down.delay = 10*time.Millisecond, 10*time.Millisecond
	n.relay = NewRelay(rc, n.now)
	n.client = n.newClient(cc)
	return n
}

func (n *network) newClient(cc ClientConfig) *Client {
	n.t.Helper()
	if cc.Static.Public == nil {
		cc.Static = clientKey
	}
	if cc.RelayPublic == nil {
		cc.RelayPublic = relayKey.Public
	}
	if cc.Credential == nil {
		cc.Credential = []byte("good")
	}
	if cc.Rand == nil {
		cc.Rand = rand.NewChaCha8([32]byte{byte(n.rng.Uint32()), byte(n.rng.Uint32())})
	}
	c, err := NewClient(cc, n.now)
	if err != nil {
		n.t.Fatal(err)
	}
	return c
}

func (n *network) send(toRelay bool, data []byte) {
	if n.tap != nil {
		n.tap(toRelay, data)
	}
	l := n.down
	if toRelay {
		l = n.up
	}
	copies := 1
	if n.rng.Float64() < l.dup {
		copies = 2
	}
	for range copies {
		if l.down || n.rng.Float64() < l.loss {
			continue
		}
		at := n.now.Add(l.delay)
		if l.jitter > 0 {
			at = at.Add(time.Duration(n.rng.Int64N(int64(l.jitter))))
		}
		n.seq++
		n.inflight = append(n.inflight, delivery{at: at, seq: n.seq, toRelay: toRelay, data: data})
	}
}

// pump moves outgoing datagrams onto the link and collects events.
func (n *network) pump() {
	for {
		d, ok := n.client.PollTransmit()
		if !ok {
			break
		}
		n.send(true, d.Data)
	}
	for {
		d, ok := n.relay.PollTransmit()
		if !ok {
			break
		}
		if d.Addr != n.clientAddr {
			n.t.Fatalf("relay sent to unexpected address %v", d.Addr)
		}
		n.send(false, d.Data)
	}
	for {
		e, ok := n.client.PollEvent()
		if !ok {
			break
		}
		n.clientEvents = append(n.clientEvents, e)
	}
	for {
		e, ok := n.relay.PollEvent()
		if !ok {
			break
		}
		n.relayEvents = append(n.relayEvents, e)
	}
}

// step advances the clock to the next delivery or timer and processes it.
// It returns false when nothing remains to do.
func (n *network) step() bool {
	n.pump()
	next := earliest(n.client.NextDeadline(), n.relay.NextDeadline())
	if len(n.inflight) > 0 {
		sort.Slice(n.inflight, func(i, j int) bool {
			a, b := n.inflight[i], n.inflight[j]
			return a.at.Before(b.at) || (a.at.Equal(b.at) && a.seq < b.seq)
		})
		next = earliest(next, n.inflight[0].at)
	}
	if next.IsZero() {
		return false
	}
	if next.After(n.now) {
		n.now = next
	}
	for len(n.inflight) > 0 && !n.inflight[0].at.After(n.now) {
		d := n.inflight[0]
		n.inflight = n.inflight[1:]
		if d.toRelay {
			n.relay.HandlePacket(n.now, n.clientAddr, d.data)
		} else {
			n.client.HandlePacket(n.now, 0, d.data)
		}
	}
	n.client.Tick(n.now)
	n.relay.Tick(n.now)
	n.pump()
	return true
}

// runUntil steps until cond holds or the simulated time limit passes.
func (n *network) runUntil(limit time.Duration, cond func() bool) bool {
	end := n.now.Add(limit)
	for !cond() {
		if n.now.After(end) || !n.step() {
			return cond()
		}
	}
	return true
}

// runFor advances simulated time by d, processing everything due.
func (n *network) runFor(d time.Duration) {
	end := n.now.Add(d)
	for n.now.Before(end) {
		if !n.step() {
			n.now = end
		}
	}
}

func (n *network) establish() *RelaySession {
	n.t.Helper()
	if !n.runUntil(30*time.Second, func() bool { return n.client.State() == StateActive }) {
		n.t.Fatalf("client did not become active (state %v)", n.client.State())
	}
	n.runUntil(time.Second, func() bool { return n.relaySession() != nil })
	s := n.relaySession()
	if s == nil {
		n.t.Fatal("relay reported no session")
	}
	return s
}

func (n *network) relaySession() *RelaySession {
	for _, e := range n.relayEvents {
		if e, ok := e.(SessionEstablished); ok {
			return e.Session
		}
	}
	return nil
}

func (n *network) clientIPs() [][]byte {
	var out [][]byte
	for _, e := range n.clientEvents {
		if e, ok := e.(IPReceived); ok {
			out = append(out, e.Packet)
		}
	}
	return out
}

func (n *network) relayIPs() [][]byte {
	var out [][]byte
	for _, e := range n.relayEvents {
		if e, ok := e.(SessionIP); ok {
			out = append(out, e.Packet)
		}
	}
	return out
}

func (n *network) clientClosed() error {
	for _, e := range n.clientEvents {
		if e, ok := e.(Closed); ok {
			return e.Err
		}
	}
	return nil
}

// ipPacket builds an IPv4 packet of the given size with a sequence number
// in its payload.
func ipPacket(src, dst [4]byte, size int, seq uint32) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	p[8], p[9] = 64, 17
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint32(p[20:24], seq)
	for i := 24; i < size; i++ {
		p[i] = byte(seq) ^ byte(i)
	}
	return p
}

func seqOf(p []byte) uint32 { return binary.BigEndian.Uint32(p[20:24]) }

var internet = [4]byte{198, 51, 100, 7}
