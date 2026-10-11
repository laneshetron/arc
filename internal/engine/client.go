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

// ClientConfig configures a client engine.
type ClientConfig struct {
	Session session.ClientConfig
	Relay   netip.AddrPort
	Conn    DatagramConn // path 0 carrier
	TUN     PacketDevice

	// OnEstablished configures the local network (address, MTU, routes)
	// each time a session becomes active. A reconnect may lease a
	// different address.
	OnEstablished func(wire.AuthResult) error

	// ReconnectDelay is the pause before replacing a session that ended
	// for a reason other than authentication failure. Default 1 s.
	ReconnectDelay time.Duration
	Logger         *slog.Logger
}

// RunClient runs sessions until ctx is canceled, authentication fails, or
// an I/O error occurs. It reconnects after resets and timeouts. The caller
// owns Conn and TUN and must close them after RunClient returns, which
// also stops the reader goroutines.
func RunClient(ctx context.Context, cfg ClientConfig) error {
	if cfg.ReconnectDelay == 0 {
		cfg.ReconnectDelay = time.Second
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	udpCh, tunCh, errc := make(chan datagrams, 16), make(chan [][]byte, 16), make(chan error, 2)
	go readDatagrams(ctx, cfg.Conn, udpCh, errc)
	go readPackets(ctx, cfg.TUN, tunCh, errc)

	c, err := session.NewClient(cfg.Session, time.Now())
	if err != nil {
		return err
	}
	log.Info("connecting", "relay", cfg.Relay)
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var reconnectAt time.Time
	var out, toTUN [][]byte
	var to []netip.AddrPort

	for {
		// Flush everything the session produced.
		out, to = out[:0], to[:0]
		for d, ok := c.PollTransmit(); ok; d, ok = c.PollTransmit() {
			if d.PathID == 0 {
				out, to = append(out, d.Data), append(to, cfg.Relay)
			}
		}
		if len(out) > 0 {
			if err := cfg.Conn.WriteBatch(out, to); err != nil {
				log.Warn("send failed", "err", err)
			}
		}
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
		if !reconnectAt.IsZero() {
			deadline = reconnectAt
		}
		resetTimer(timer, deadline)

		select {
		case <-ctx.Done():
			c.Close(time.Now())
			for d, ok := c.PollTransmit(); ok; d, ok = c.PollTransmit() {
				cfg.Conn.WriteBatch([][]byte{d.Data}, []netip.AddrPort{cfg.Relay})
			}
			return ctx.Err()
		case err := <-errc:
			return err
		case d := <-udpCh:
			now := time.Now()
			for i, p := range d.pkts {
				if d.from[i] == cfg.Relay {
					c.HandlePacket(now, 0, p)
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
				if c, err = session.NewClient(cfg.Session, now); err != nil {
					return err
				}
				log.Info("connecting", "relay", cfg.Relay)
				continue
			}
			c.Tick(now)
		}
	}
}
