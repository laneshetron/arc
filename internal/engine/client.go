package engine

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/laneshetron/arc/internal/bufpool"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// Carrier is one underlay the client can reach the relay through, such as
// a socket bound to one network interface.
type Carrier struct {
	Name string // for logs, e.g. the interface name
	Conn DatagramConn
	// Relay is the relay address this carrier sends to and accepts
	// packets from; zero means ClientConfig.Relay. A stream carrier sends
	// to its own endpoint and reports packets as coming from Relay.
	Relay netip.AddrPort
	// Fallback marks the carrier's path for use only while no other path
	// is healthy, as for TLS/TCP (spec §16.3).
	Fallback bool
}

// ClientConfig configures a client engine.
type ClientConfig struct {
	Session  session.ClientConfig
	Relay    netip.AddrPort
	Carriers []Carrier // at least one
	TUN      PacketDevice

	// OnEstablished configures the local network (address, MTU, routes)
	// each time a session becomes active. A reconnect may lease a
	// different address.
	OnEstablished func(wire.AuthResult) error

	// ReconnectDelay is the pause before replacing a session that ended
	// for a reason other than authentication failure. Default 1 s.
	ReconnectDelay time.Duration
	// RejoinDelay is the pause before a carrier whose path closed tries to
	// join the session again. Default 5 s.
	RejoinDelay time.Duration
	Logger      *slog.Logger

	// StatusInterval, if nonzero, logs each path's state that often.
	StatusInterval time.Duration
}

// carrierState records which session path, if any, a carrier carries.
type carrierState struct {
	Carrier
	bound   bool
	path    uint32
	retryAt time.Time // when an unbound carrier may next try to join

	out [][]byte         // reused per flush: datagrams for this carrier
	to  []netip.AddrPort // and their destinations
}

// slotRetry is how soon to retry joining when the relay has not issued a
// path slot yet.
const slotRetry = 200 * time.Millisecond

// RunClient runs sessions until ctx is canceled, authentication fails, or
// an I/O error occurs. It reconnects after resets and timeouts.
//
// Each handshake goes out on every carrier at once, and the carrier the
// relay's response arrives on becomes path 0: on links that lose most
// packets, more attempts per second is what gets a session up, and a dead
// link cannot block one. Once the session is active, each other carrier
// joins as another path, and a carrier whose path closes rejoins after
// RejoinDelay.
//
// The caller owns the carriers' connections and the TUN and must close
// them after RunClient returns, which also stops the reader goroutines.
func RunClient(ctx context.Context, cfg ClientConfig) error {
	if len(cfg.Carriers) == 0 {
		return errors.New("engine: no carriers")
	}
	if cfg.ReconnectDelay == 0 {
		cfg.ReconnectDelay = time.Second
	}
	if cfg.RejoinDelay == 0 {
		cfg.RejoinDelay = 5 * time.Second
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	udpCh, tunCh := make(chan datagrams, 16), make(chan [][]byte, 16)
	errc := make(chan error, len(cfg.Carriers)+1)
	carriers := make([]*carrierState, len(cfg.Carriers))
	for i, cr := range cfg.Carriers {
		if !cr.Relay.IsValid() {
			cr.Relay = cfg.Relay
		}
		carriers[i] = &carrierState{Carrier: cr}
		go readDatagrams(ctx, i, cr.Conn, udpCh, errc)
	}
	go readPackets(ctx, cfg.TUN, tunCh, errc)

	// hs tracks where handshake packets go: every carrier, or only the one
	// a COOKIE_REPLY arrived on, since the cookie is valid only for that
	// carrier's address (§9.3).
	hs := handshakeState{pinned: -1}
	newSession := func(now time.Time) (*session.Client, error) {
		log.Info("connecting", "relay", cfg.Relay, "carriers", len(carriers))
		return session.NewClient(cfg.Session, now)
	}

	c, err := newSession(time.Now())
	if err != nil {
		return err
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var status <-chan time.Time
	if cfg.StatusInterval > 0 {
		t := time.NewTicker(cfg.StatusInterval)
		defer t.Stop()
		status = t.C
	}
	var reconnectAt time.Time
	var toTUN [][]byte

	for {
		hs.update(c, carriers)
		joinCarriers(c, carriers, cfg.RejoinDelay, log)
		flushTransmits(c, carriers, hs.pinned, log)
		toTUN = toTUN[:0]
		for e, ok := c.PollEvent(); ok; e, ok = c.PollEvent() {
			switch e := e.(type) {
			case session.Established:
				addr := netip.AddrFrom4(e.Config.IPv4)
				log.Info("session established", "address", netip.PrefixFrom(addr, int(e.Config.Prefix4)), "mtu", e.Config.TunMTU)
				if cfg.OnEstablished != nil {
					if err := cfg.OnEstablished(e.Config); err != nil {
						c.Close(time.Now())
						return err
					}
				}
			case session.PathValidated:
				log.Info("path validated", "path", e.ID)
			case session.RedundancyChanged:
				log.Info("redundancy changed", "uplink", e.Uplink, "downlink", e.Downlink)
			case session.PathClosed:
				log.Info("path closed", "path", e.ID, "reason", e.Err)
				for _, cs := range carriers {
					if cs.bound && cs.path == e.ID {
						cs.bound = false
						cs.retryAt = time.Now().Add(cfg.RejoinDelay)
						break
					}
				}
			case session.Closed:
				if errors.Is(e.Err, session.ErrAuthFailed) {
					return e.Err
				}
				log.Warn("session ended; reconnecting", "reason", e.Err, "after", cfg.ReconnectDelay)
				reconnectAt = time.Now().Add(cfg.ReconnectDelay)
			}
		}
		for p, ok := c.PollIP(); ok; p, ok = c.PollIP() {
			toTUN = append(toTUN, p)
		}
		if len(toTUN) > 0 {
			if err := cfg.TUN.Write(toTUN); err != nil {
				log.Warn("tun write failed", "err", err)
			}
			for _, p := range toTUN {
				bufpool.Put(p)
			}
		}

		deadline := c.NextDeadline()
		if c.State() == session.StateActive {
			for _, cs := range carriers {
				if cs.bound {
					continue
				}
				due := cs.retryAt
				if due.IsZero() { // never tried: join now
					due = time.Now()
				}
				if deadline.IsZero() || due.Before(deadline) {
					deadline = due
				}
			}
		}
		if !reconnectAt.IsZero() {
			deadline = reconnectAt
		}
		resetTimer(timer, deadline)

		select {
		case <-ctx.Done():
			c.Close(time.Now())
			flushTransmits(c, carriers, hs.pinned, log)
			return ctx.Err()
		case err := <-errc:
			return err
		case d := <-udpCh:
			cs := carriers[d.carrier]
			now := time.Now()
			for i, p := range d.pkts {
				switch {
				case d.from[i] != cs.Relay:
				case cs.bound:
					c.HandlePacket(now, cs.path, p)
				case c.State() == session.StateHandshaking:
					hs.receive(c, now, d.carrier, carriers, p)
				}
				bufpool.Put(p) // the session keeps no reference to its input
			}
		case pkts := <-tunCh:
			now := time.Now()
			for _, p := range pkts {
				c.SendIP(now, p) // dropped while not active, like an unplugged link
				bufpool.Put(p)   // SendIP copied what it needed
			}
		case <-status:
			logPaths(log, c, carriers, time.Now())
		case <-timer.C:
			now := time.Now()
			if !reconnectAt.IsZero() && !now.Before(reconnectAt) {
				reconnectAt = time.Time{}
				if c, err = newSession(now); err != nil {
					return err
				}
				continue
			}
			c.Tick(now)
		}
	}
}

// joinCarriers binds eligible underlays to new paths in the active session.
func joinCarriers(c *session.Client, carriers []*carrierState, rejoinDelay time.Duration, log *slog.Logger) {
	if c.State() != session.StateActive {
		return
	}
	now := time.Now()
	for _, cs := range carriers {
		if cs.bound || now.Before(cs.retryAt) {
			continue
		}
		id, err := c.OpenPath(now)
		switch {
		case err == nil:
			cs.bound, cs.path = true, id
			if cs.Fallback {
				c.SetFallback(id, true)
			}
		case errors.Is(err, session.ErrNoPathSlots):
			cs.retryAt = now.Add(slotRetry)
		default:
			cs.retryAt = now.Add(rejoinDelay)
			log.Warn("joining carrier failed", "carrier", cs.Name, "err", err)
		}
	}
}

// handshakeState steers handshake packets across carriers.
type handshakeState struct {
	client  *session.Client
	attempt uint64
	pinned  int // carrier holding the attempt's cookie, or -1 for all
	active  bool
}

// update unbinds every carrier when a handshake attempt starts, since path
// 0 will be whichever carrier the response arrives on.
func (h *handshakeState) update(c *session.Client, carriers []*carrierState) {
	handshaking := c.State() == session.StateHandshaking
	if handshaking && (!h.active || c != h.client || c.HandshakeAttempt() != h.attempt) {
		for _, cs := range carriers {
			cs.bound, cs.path, cs.retryAt = false, 0, time.Time{}
		}
		h.client, h.attempt, h.pinned = c, c.HandshakeAttempt(), -1
	}
	h.active = handshaking
}

// receive handles a packet from the relay on an unbound carrier during the
// handshake, binding that carrier to path 0 if it completes the handshake.
func (h *handshakeState) receive(c *session.Client, now time.Time, carrier int, carriers []*carrierState, p []byte) {
	if t, err := wire.PeekType(p); err == nil && t == wire.TypeCookieReply {
		h.pinned = carrier
	}
	c.HandlePacket(now, 0, p)
	if c.State() != session.StateHandshaking {
		cs := carriers[carrier]
		cs.bound, cs.path = true, 0
		if cs.Fallback {
			c.SetFallback(0, true)
		}
	}
}

// flushTransmits batches outgoing datagrams by their bound carrier. While
// handshaking, path 0's datagrams go to every carrier, or to pinned if it
// is not -1.
func flushTransmits(c *session.Client, carriers []*carrierState, pinned int, log *slog.Logger) {
	handshaking := c.State() == session.StateHandshaking
	for d, ok := c.PollTransmit(); ok; d, ok = c.PollTransmit() {
		if handshaking && d.PathID == 0 {
			for i, cs := range carriers {
				if pinned < 0 || i == pinned {
					// A copy each: the buffers are returned per carrier.
					cs.out, cs.to = append(cs.out, append(bufpool.Get(), d.Data...)), append(cs.to, cs.Relay)
				}
			}
			bufpool.Put(d.Data)
			continue
		}
		sent := false
		for _, cs := range carriers {
			if cs.bound && cs.path == d.PathID {
				cs.out, cs.to = append(cs.out, d.Data), append(cs.to, cs.Relay)
				sent = true
				break
			}
		}
		if !sent {
			bufpool.Put(d.Data)
		}
	}
	for _, cs := range carriers {
		if len(cs.out) == 0 {
			continue
		}
		if err := cs.Conn.WriteBatch(cs.out, cs.to); err != nil {
			log.Warn("send failed", "carrier", cs.Name, "err", err)
		}
		// WriteBatch has copied or sent everything; the buffers are free.
		for i, p := range cs.out {
			bufpool.Put(p)
			cs.out[i] = nil
		}
		cs.out, cs.to = cs.out[:0], cs.to[:0]
	}
}

// logPaths logs each path's state, for -status.
func logPaths(log *slog.Logger, c *session.Client, carriers []*carrierState, now time.Time) {
	if c.State() != session.StateActive {
		return
	}
	for _, p := range c.Paths(now) {
		carrier := ""
		for _, cs := range carriers {
			if cs.bound && cs.path == p.ID {
				carrier = cs.Name
			}
		}
		log.Info("path", "id", p.ID, "carrier", carrier, "primary", p.Primary, "healthy", p.Healthy, "eligible", p.Eligible,
			"flows", p.Flows, "min_rtt", p.MinRTT.Round(100*time.Microsecond), "srtt", p.SRTT.Round(100*time.Microsecond),
			"loss", fmt.Sprintf("%.3f", p.Loss), "burst", fmt.Sprintf("%.1f", p.Burst), "capacity_mbit", fmt.Sprintf("%.1f", p.Capacity*8/1e6))
	}
}
