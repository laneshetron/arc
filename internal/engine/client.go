package engine

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// Carrier is one underlay the client can reach the relay through, such as
// a socket bound to one network interface.
type Carrier struct {
	Name string // for logs, e.g. the interface name
	Conn DatagramConn
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
}

// carrierState records which session path, if any, a carrier carries.
type carrierState struct {
	Carrier
	bound   bool
	path    uint32
	retryAt time.Time // when an unbound carrier may next try to join
}

// slotRetry is how soon to retry joining when the relay has not issued a
// path slot yet.
const slotRetry = 200 * time.Millisecond

// RunClient runs sessions until ctx is canceled, authentication fails, or
// an I/O error occurs. It reconnects after resets and timeouts.
//
// Each session handshakes on one carrier, which becomes path 0. Once the
// session is active, each other carrier joins as another path, and a
// carrier whose path closes rejoins after RejoinDelay. Successive sessions
// rotate the handshake carrier, so one dead link cannot block reconnecting.
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
		carriers[i] = &carrierState{Carrier: cr}
		go readDatagrams(ctx, i, cr.Conn, udpCh, errc)
	}
	go readPackets(ctx, cfg.TUN, tunCh, errc)

	attempt := 0
	newSession := func(now time.Time) (*session.Client, error) {
		first := attempt % len(carriers)
		attempt++
		for i, cs := range carriers {
			cs.bound, cs.path, cs.retryAt = i == first, 0, time.Time{}
		}
		log.Info("connecting", "relay", cfg.Relay, "carrier", carriers[first].Name)
		return session.NewClient(cfg.Session, now)
	}

	c, err := newSession(time.Now())
	if err != nil {
		return err
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var reconnectAt time.Time
	var toTUN [][]byte

	for {
		joinCarriers(c, carriers, cfg.RejoinDelay, log)
		flushTransmits(c, carriers, cfg.Relay, log)
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
			case session.IPReceived:
				toTUN = append(toTUN, e.Packet)
			case session.PathValidated:
				log.Info("path validated", "path", e.ID)
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
		if len(toTUN) > 0 {
			if err := cfg.TUN.Write(toTUN); err != nil {
				log.Warn("tun write failed", "err", err)
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
			flushTransmits(c, carriers, cfg.Relay, log)
			return ctx.Err()
		case err := <-errc:
			return err
		case d := <-udpCh:
			cs := carriers[d.carrier]
			if !cs.bound {
				continue
			}
			now := time.Now()
			for i, p := range d.pkts {
				if d.from[i] == cfg.Relay {
					c.HandlePacket(now, cs.path, p)
				}
			}
		case pkts := <-tunCh:
			now := time.Now()
			for _, p := range pkts {
				c.SendIP(now, p) // dropped while not active, like an unplugged link
			}
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
		case errors.Is(err, session.ErrNoPathSlots):
			cs.retryAt = now.Add(slotRetry)
		default:
			cs.retryAt = now.Add(rejoinDelay)
			log.Warn("joining carrier failed", "carrier", cs.Name, "err", err)
		}
	}
}

// flushTransmits batches outgoing datagrams by their bound carrier.
func flushTransmits(c *session.Client, carriers []*carrierState, relay netip.AddrPort, log *slog.Logger) {
	groups := make([][][]byte, len(carriers))
	for d, ok := c.PollTransmit(); ok; d, ok = c.PollTransmit() {
		for i, cs := range carriers {
			if cs.bound && cs.path == d.PathID {
				groups[i] = append(groups[i], d.Data)
				break
			}
		}
	}
	for i, pkts := range groups {
		if len(pkts) == 0 {
			continue
		}
		to := make([]netip.AddrPort, len(pkts))
		for j := range to {
			to[j] = relay
		}
		if err := carriers[i].Conn.WriteBatch(pkts, to); err != nil {
			log.Warn("send failed", "carrier", carriers[i].Name, "err", err)
		}
	}
}
