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
	mtu    int           // drop larger datagrams; 0 means unlimited
	down   bool          // drop everything

	// rate limits the link to this many bytes per second, with a FIFO
	// queue holding at most queue's worth of transmission time (default
	// 50 ms); 0 means unlimited.
	rate      int
	queue     time.Duration
	busyUntil time.Time
	// lossAfterQueue loses datagrams after they cross the rate-limited
	// bottleneck, so lost ones use its capacity too, as on a lossy radio
	// hop; by default loss comes first, as with netem's loss on egress.
	lossAfterQueue bool

	// Bursty loss (Gilbert-Elliott, as netem's gemodel): per datagram the
	// link enters a bad state with probability burstP and leaves it with
	// probability burstR, losing everything while bad. Average loss is
	// burstP/(burstP+burstR) and the mean burst 1/burstR datagrams.
	burstP, burstR float64
	bad            bool
}

// lost reports whether the link loses its next datagram.
func (l *link) lost(rng *rand.Rand) bool {
	if l.down || rng.Float64() < l.loss {
		return true
	}
	if l.burstP == 0 {
		return false
	}
	if l.bad {
		l.bad = rng.Float64() >= l.burstR
	} else {
		l.bad = rng.Float64() < l.burstP
	}
	return l.bad
}

// bursty sets bursty loss averaging loss with bursts of meanBurst datagrams.
func (l *link) bursty(loss, meanBurst float64) {
	l.burstR = 1 / meanBurst
	l.burstP = loss * l.burstR / (1 - loss)
}

// carrier is one client path's network attachment: the client's address
// as the relay sees it (its NAT mapping) and a link in each direction.
type carrier struct {
	addr     netip.AddrPort
	up, down *link
}

type delivery struct {
	at      time.Time
	seq     int
	toRelay bool
	pathID  uint32
	from    netip.AddrPort
	data    []byte
}

// network connects one client and one relay over an impaired link, driven
// by a fake clock.
type network struct {
	t          *testing.T
	now        time.Time
	rng        *rand.Rand
	up, down   *link // path 0: client→relay, relay→client
	carriers   map[uint32]*carrier
	pastAddrs  map[netip.AddrPort]bool // every address a carrier ever had
	misrouted  int                     // relay datagrams to addresses no carrier holds
	bytesTo    map[netip.AddrPort]int  // relay output per destination
	inflight   []delivery
	seq        int
	client     *Client
	relay      *Relay
	clientAddr netip.AddrPort // path 0's original address

	clientEvents []ClientEvent
	relayEvents  []RelayEvent
	clientIPList [][]byte                        // IP packets the client received
	relayIPList  [][]byte                        // IP packets the relay received
	tap          func(toRelay bool, data []byte) // observes every sent datagram
	pathTap      func(toRelay bool, pathID uint32, data []byte)
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

func testAuthorizer(credential, _ []byte, _ bool) (wire.AuthResult, error) {
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
	n.up, n.down = &link{delay: 10 * time.Millisecond}, &link{delay: 10 * time.Millisecond}
	n.carriers = map[uint32]*carrier{0: {addr: n.clientAddr, up: n.up, down: n.down}}
	n.pastAddrs = map[netip.AddrPort]bool{n.clientAddr: true}
	n.bytesTo = map[netip.AddrPort]int{}
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

func (n *network) send(toRelay bool, pathID uint32, data []byte) {
	if n.tap != nil {
		n.tap(toRelay, data)
	}
	if n.pathTap != nil {
		n.pathTap(toRelay, pathID, data)
	}
	c := n.carriers[pathID]
	if c == nil {
		return
	}
	l := c.down
	if toRelay {
		l = c.up
	}
	copies := 1
	if n.rng.Float64() < l.dup {
		copies = 2
	}
	for range copies {
		if !l.lossAfterQueue && l.lost(n.rng) || (l.mtu > 0 && len(data) > l.mtu) {
			continue
		}
		at := n.now
		if l.rate > 0 {
			queue := l.queue
			if queue == 0 {
				queue = 50 * time.Millisecond
			}
			start := l.busyUntil
			if start.Before(n.now) {
				start = n.now
			}
			if start.Sub(n.now) > queue {
				continue // tail drop
			}
			l.busyUntil = start.Add(time.Duration(len(data)) * time.Second / time.Duration(l.rate))
			at = l.busyUntil
		}
		if l.lossAfterQueue && l.lost(n.rng) {
			continue
		}
		at = at.Add(l.delay)
		if l.jitter > 0 {
			at = at.Add(time.Duration(n.rng.Int64N(int64(l.jitter))))
		}
		n.seq++
		n.inflight = append(n.inflight, delivery{at: at, seq: n.seq, toRelay: toRelay, pathID: pathID, from: c.addr, data: data})
	}
}

// pump moves outgoing datagrams onto the link and collects events.
func (n *network) pump() {
	for {
		d, ok := n.client.PollTransmit()
		if !ok {
			break
		}
		n.send(true, d.PathID, d.Data)
	}
	for {
		d, ok := n.relay.PollTransmit()
		if !ok {
			break
		}
		n.bytesTo[d.Addr] += len(d.Data)
		if !n.pastAddrs[d.Addr] {
			n.t.Fatalf("relay sent to unknown address %v", d.Addr)
		}
		id, ok := n.carrierFor(d.Addr)
		if !ok {
			n.misrouted++ // an old NAT mapping: the datagram goes nowhere
			continue
		}
		n.send(false, id, d.Data)
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
	for p, ok := n.client.PollIP(); ok; p, ok = n.client.PollIP() {
		n.clientIPList = append(n.clientIPList, p)
	}
	for _, p, ok := n.relay.PollIP(); ok; _, p, ok = n.relay.PollIP() {
		n.relayIPList = append(n.relayIPList, p)
	}
}

// step advances the clock to the next delivery or timer, but never past
// limit, and processes what is due. It returns false when nothing is due
// before limit.
func (n *network) step(limit time.Time) bool {
	n.pump()
	next := earliest(n.client.NextDeadline(), n.relay.NextDeadline())
	if len(n.inflight) > 0 {
		sort.Slice(n.inflight, func(i, j int) bool {
			a, b := n.inflight[i], n.inflight[j]
			return a.at.Before(b.at) || (a.at.Equal(b.at) && a.seq < b.seq)
		})
		next = earliest(next, n.inflight[0].at)
	}
	if next.IsZero() || next.After(limit) {
		n.now = limit
		return false
	}
	if next.After(n.now) {
		n.now = next
	}
	for len(n.inflight) > 0 && !n.inflight[0].at.After(n.now) {
		d := n.inflight[0]
		n.inflight = n.inflight[1:]
		if d.toRelay {
			n.relay.HandlePacket(n.now, d.from, d.data)
		} else {
			n.client.HandlePacket(n.now, d.pathID, d.data)
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
		if !n.now.Before(end) {
			return false
		}
		n.step(end)
	}
	return true
}

// runFor advances simulated time by d, processing everything due.
func (n *network) runFor(d time.Duration) {
	end := n.now.Add(d)
	for n.now.Before(end) {
		n.step(end)
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

func (n *network) clientIPs() [][]byte { return n.clientIPList }

func (n *network) relayIPs() [][]byte { return n.relayIPList }

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
// ipPacket returns a UDP/IPv4 packet of one flow (fixed ports) carrying
// seq after the UDP header; size must be at least 32.
func ipPacket(src, dst [4]byte, size int, seq uint32) []byte {
	return flowPacket(src, dst, 40000, 4000, size, seq)
}

// flowPacket is ipPacket with the source and destination ports given.
func flowPacket(src, dst [4]byte, sport, dport uint16, size int, seq uint32) []byte {
	p := make([]byte, size)
	p[0] = 0x45
	binary.BigEndian.PutUint16(p[2:4], uint16(size))
	p[8], p[9] = 64, 17
	copy(p[12:16], src[:])
	copy(p[16:20], dst[:])
	binary.BigEndian.PutUint16(p[20:22], sport)
	binary.BigEndian.PutUint16(p[22:24], dport)
	binary.BigEndian.PutUint16(p[24:26], uint16(size-20))
	binary.BigEndian.PutUint32(p[28:32], seq)
	for i := 32; i < size; i++ {
		p[i] = byte(seq) ^ byte(i)
	}
	return p
}

func seqOf(p []byte) uint32 { return binary.BigEndian.Uint32(p[28:32]) }

var internet = [4]byte{198, 51, 100, 7}

func (n *network) carrierFor(addr netip.AddrPort) (uint32, bool) {
	for id, c := range n.carriers {
		if c.addr == addr {
			return id, true
		}
	}
	return 0, false
}

// openPath opens a client path over a new carrier with its own address and
// links, and returns its ID.
func (n *network) openPath(addr string, delay time.Duration) (uint32, *carrier) {
	n.t.Helper()
	id, err := n.client.OpenPath(n.now)
	if err != nil {
		n.t.Fatal(err)
	}
	c := &carrier{addr: netip.MustParseAddrPort(addr), up: &link{delay: delay}, down: &link{delay: delay}}
	n.carriers[id] = c
	n.pastAddrs[c.addr] = true
	return id, c
}

// rebind changes a carrier's NAT mapping, as a NAT timeout would.
func (n *network) rebind(id uint32, addr string) {
	c := n.carriers[id]
	c.addr = netip.MustParseAddrPort(addr)
	n.pastAddrs[c.addr] = true
}

func (n *network) clientEventsOf(match func(ClientEvent) bool) int {
	k := 0
	for _, e := range n.clientEvents {
		if match(e) {
			k++
		}
	}
	return k
}

func TestBurstyLinkModel(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	var l link
	l.bursty(0.05, 10)
	lost, bursts, run := 0, 0, 0
	const n = 1_000_000
	for range n {
		if l.lost(rng) {
			lost++
			run++
		} else if run > 0 {
			bursts++
			run = 0
		}
	}
	rate, mean := float64(lost)/n, float64(lost)/float64(bursts)
	if rate < 0.045 || rate > 0.055 || mean < 9 || mean > 11 {
		t.Errorf("loss %.4f in bursts of %.1f; want 0.05 in bursts of 10", rate, mean)
	}
}
