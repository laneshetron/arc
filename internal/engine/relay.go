package engine

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/laneshetron/arc/internal/bufpool"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/session"
)

// RelayConfig configures a relay engine. Session.Authorize is set to
// Gateway.Authorize.
type RelayConfig struct {
	Session session.RelayConfig
	Conn    DatagramConn
	TUN     PacketDevice
	Gateway *gateway.Gateway
	Logger  *slog.Logger
}

// RunRelay runs the relay until ctx is canceled or an I/O error occurs. The
// caller owns Conn and TUN and must close them after RunRelay returns.
func RunRelay(ctx context.Context, cfg RelayConfig) error {
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	udpCh, tunCh, errc := make(chan datagrams, 16), make(chan [][]byte, 16), make(chan error, 2)
	go readDatagrams(ctx, 0, cfg.Conn, udpCh, errc)
	go readPackets(ctx, cfg.TUN, tunCh, errc)

	cfg.Session.Authorize = cfg.Gateway.Authorize
	r := session.NewRelay(cfg.Session, time.Now())
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var out, toTUN [][]byte
	var to []netip.AddrPort

	for {
		out, to = out[:0], to[:0]
		for d, ok := r.PollTransmit(); ok; d, ok = r.PollTransmit() {
			out, to = append(out, d.Data), append(to, d.Addr)
		}
		if len(out) > 0 {
			if err := cfg.Conn.WriteBatch(out, to); err != nil {
				log.Warn("send failed", "err", err)
			}
			for _, p := range out {
				bufpool.Put(p)
			}
		}
		toTUN = toTUN[:0]
		for e, ok := r.PollEvent(); ok; e, ok = r.PollEvent() {
			switch e := e.(type) {
			case session.SessionEstablished:
				cfg.Gateway.Bind(e.Session)
				log.Info("session established", "client", e.Session.Addr(time.Now()),
					"address", netip.AddrFrom4(e.Session.Config().IPv4))
			case session.SessionIP:
				toTUN = append(toTUN, e.Packet)
			case session.SessionClosed:
				cfg.Gateway.Release(e.Session)
				log.Info("session closed", "address", netip.AddrFrom4(e.Session.Config().IPv4), "reason", e.Err)
			}
		}
		if len(toTUN) > 0 {
			if err := cfg.TUN.Write(toTUN); err != nil {
				log.Warn("tun write failed", "err", err)
			}
			for _, p := range toTUN {
				bufpool.Put(p)
			}
		}
		resetTimer(timer, r.NextDeadline())

		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errc:
			return err
		case d := <-udpCh:
			now := time.Now()
			for i, p := range d.pkts {
				r.HandlePacket(now, d.from[i], p)
				bufpool.Put(p) // the session keeps no reference to its input
			}
		case pkts := <-tunCh:
			now := time.Now()
			for _, p := range pkts {
				if s := cfg.Gateway.Lookup(p); s != nil {
					s.SendIP(now, p)
				}
				bufpool.Put(p) // SendIP copied what it needed
			}
		case <-timer.C:
			r.Tick(time.Now())
		}
	}
}
