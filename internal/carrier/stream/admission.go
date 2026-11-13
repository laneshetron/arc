package stream

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// admissionLimits bound the TCP connections a relay endpoint holds,
// counted by the peer's real IP before any synthetic stream address is
// assigned. A connection is pending until it becomes a carrier: during
// its TLS handshake on the plain listener, or for its whole life as an
// HTTP visitor on the front. Pending work has its own, smaller budgets,
// so it cannot crowd out established carriers.
type admissionLimits struct {
	maxConns, maxPending                   int
	maxConnsPerSource, maxPendingPerSource int
}

// admission counts the connections an endpoint has accepted, pending or
// established, against its limits.
type admission struct {
	limits admissionLimits

	mu             sync.Mutex
	closed         bool
	permits        map[net.Conn]*permit // every admitted connection
	pending        int
	sources        map[netip.Addr]int
	pendingSources map[netip.Addr]int
	refused        Refusals
	refusedSources map[netip.Addr]int // since the last Refusals, bounded
}

// Refusals counts TCP connections an endpoint closed at once, before any
// TLS work, because an admission limit was reached. Each reason is the
// first limit the connection hit.
type Refusals struct {
	Full              int // every connection slot taken
	Pending           int // every handshake (or visitor) slot taken
	Source            int // the source's connections at its limit
	SourcePending     int // the source's pending connections at its limit
	Sources           int // distinct sources refused, up to refusedSourcesMax
	TopSource         netip.Addr
	TopSourceRefusals int
}

// Total is the number of connections refused.
func (r Refusals) Total() int { return r.Full + r.Pending + r.Source + r.SourcePending }

const refusedSourcesMax = 1024

// refusal returns the counter of the first limit a new connection from
// source would exceed, or nil if it may be admitted.
func (a *admission) refusal(source netip.Addr) *int {
	switch {
	case len(a.permits) >= a.limits.maxConns:
		return &a.refused.Full
	case a.pending >= a.limits.maxPending:
		return &a.refused.Pending
	case a.sources[source] >= a.limits.maxConnsPerSource:
		return &a.refused.Source
	case a.pendingSources[source] >= a.limits.maxPendingPerSource:
		return &a.refused.SourcePending
	}
	return nil
}

// takeRefusals returns the refusals since it was last called, and starts
// counting afresh.
func (a *admission) takeRefusals() Refusals {
	a.mu.Lock()
	defer a.mu.Unlock()
	r := a.refused
	r.Sources = len(a.refusedSources)
	for src, n := range a.refusedSources {
		if n > r.TopSourceRefusals || (n == r.TopSourceRefusals && src.Less(r.TopSource)) {
			r.TopSource, r.TopSourceRefusals = src, n
		}
	}
	a.refused = Refusals{}
	clear(a.refusedSources)
	return r
}

// permit is one admitted connection's share of the limits.
type permit struct {
	a        *admission
	conn     net.Conn
	source   netip.Addr
	pending  bool
	released bool
}

func newAdmission(limits admissionLimits) *admission {
	return &admission{
		limits:  limits,
		permits: make(map[net.Conn]*permit), sources: make(map[netip.Addr]int), pendingSources: make(map[netip.Addr]int),
		refusedSources: make(map[netip.Addr]int),
	}
}

// admit counts conn as a new pending connection, or returns nil if a
// limit is reached, its peer address is unusable, or the endpoint has
// closed; the caller then closes conn.
func (a *admission) admit(conn net.Conn) *permit {
	peer, err := netip.ParseAddrPort(conn.RemoteAddr().String())
	if err != nil {
		return nil
	}
	source := peer.Addr().Unmap()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil
	}
	if r := a.refusal(source); r != nil {
		*r++
		if _, ok := a.refusedSources[source]; ok || len(a.refusedSources) < refusedSourcesMax {
			a.refusedSources[source]++
		}
		return nil
	}
	p := &permit{a: a, conn: conn, source: source, pending: true}
	a.permits[conn] = p
	a.sources[source]++
	a.pendingSources[source]++
	a.pending++
	return p
}

// established moves p from the pending budgets to the carrier it became.
// Its total and per-source permits remain held until release.
func (p *permit) established() {
	a := p.a
	a.mu.Lock()
	defer a.mu.Unlock()
	if p.pending && !p.released {
		a.finishPending(p)
	}
}

func (a *admission) finishPending(p *permit) {
	p.pending = false
	a.pending--
	a.pendingSources[p.source]--
	if a.pendingSources[p.source] == 0 {
		delete(a.pendingSources, p.source)
	}
}

// release returns every budget p holds. It is safe to call twice.
func (p *permit) release() {
	a := p.a
	a.mu.Lock()
	defer a.mu.Unlock()
	if p.released {
		return
	}
	if p.pending {
		a.finishPending(p)
	}
	p.released = true
	a.sources[p.source]--
	if a.sources[p.source] == 0 {
		delete(a.sources, p.source)
	}
	delete(a.permits, p.conn)
}

// closeAll refuses further connections and closes every admitted one,
// pending handshakes included. Their owners release the permits.
func (a *admission) closeAll() {
	a.mu.Lock()
	a.closed = true
	conns := make([]net.Conn, 0, len(a.permits))
	for c := range a.permits {
		conns = append(conns, c)
	}
	a.mu.Unlock()
	for _, c := range conns {
		c.Close()
	}
}

// counts reports admitted connections, pending ones, and the admitted
// connections per source, for tests and status.
func (a *admission) counts() (conns, pending int, sources, pendingSources int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.permits), a.pending, len(a.sources), len(a.pendingSources)
}

// admittedListener applies an admission to every connection its inner
// listener accepts, before any TLS work: excess connections are closed
// at once. Each returned connection releases its permit when closed.
type admittedListener struct {
	net.Listener
	adm *admission
}

func (l *admittedListener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		if p := l.adm.admit(c); p != nil {
			return &admittedConn{Conn: &countedConn{Conn: c, accepted: time.Now()}, permit: p}, nil
		}
		c.Close()
	}
}

// admittedConn is a connection holding a permit until it closes.
type admittedConn struct {
	net.Conn
	permit *permit
}

func (c *admittedConn) Close() error {
	err := c.Conn.Close()
	c.permit.release()
	return err
}
