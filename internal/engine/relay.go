package engine

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/laneshetron/arc/internal/bufpool"
	"github.com/laneshetron/arc/internal/carrier/stream"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// RelayConfig configures a relay engine. Session.Authorize is set to
// Gateway.Authorize.
type RelayConfig struct {
	Session session.RelayConfig
	Conn    DatagramConn
	// Streams, if set, accepts TLS/TCP carrier connections (a
	// *stream.Listener). Packets for its synthetic addresses go to it,
	// everything else to Conn.
	Streams DatagramConn
	TUN     PacketDevice
	Gateway *gateway.Gateway
	Logger  *slog.Logger

	// StatusInterval, if nonzero, logs each session's paths that often.
	StatusInterval time.Duration

	// Dial connects a client's stream (spec §11.3) to its destination,
	// once Gateway.AllowDial permits it; nil uses a net.Dialer with
	// DialTimeout. Streams are declined with Session.NoStreams.
	Dial func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
	// AllowDial overrides Gateway.AllowDial, for tests.
	AllowDial func(dst netip.AddrPort) bool
}

// DialTimeout bounds how long the relay tries to connect a stream.
const DialTimeout = 15 * time.Second

// streamKey names a stream on the relay.
type streamKey struct {
	s  *session.RelaySession
	id uint32
}

// dialResult is a finished connection attempt for a stream.
type dialResult struct {
	key  streamKey
	conn net.Conn
	err  error
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

	udpCh, tunCh, errc := make(chan datagrams, 16), make(chan [][]byte, 16), make(chan error, 3)
	go readDatagrams(ctx, 0, cfg.Conn, udpCh, errc)
	if cfg.Streams != nil {
		go readDatagrams(ctx, 1, cfg.Streams, udpCh, errc)
	}
	go readPackets(ctx, cfg.TUN, tunCh, errc)

	cfg.Session.Authorize = cfg.Gateway.Authorize
	r := session.NewRelay(cfg.Session, time.Now())
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var status <-chan time.Time
	if cfg.StatusInterval > 0 {
		t := time.NewTicker(cfg.StatusInterval)
		defer t.Stop()
		status = t.C
	}
	var out, sout, toTUN [][]byte
	var to, sto []netip.AddrPort

	dial := cfg.Dial
	if dial == nil {
		d := &net.Dialer{Timeout: DialTimeout}
		dial = func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
			return d.DialContext(ctx, "tcp", dst.String())
		}
	}
	allow := cfg.AllowDial
	if allow == nil {
		allow = cfg.Gateway.AllowDial
	}
	bridges := map[streamKey]*bridge{}
	bridgeEvents, dials := make(chan bridgeEvent, 64), make(chan dialResult, 64)
	defer func() {
		for _, b := range bridges {
			b.finish(true)
		}
	}()

	for {
		out, to, sout, sto = out[:0], to[:0], sout[:0], sto[:0]
		for d, ok := r.PollTransmit(); ok; d, ok = r.PollTransmit() {
			if cfg.Streams != nil && stream.IsStreamAddr(d.Addr) {
				sout, sto = append(sout, d.Data), append(sto, d.Addr)
			} else {
				out, to = append(out, d.Data), append(to, d.Addr)
			}
		}
		for i, batch := range [][][]byte{out, sout} {
			if len(batch) == 0 {
				continue
			}
			conn, addrs := cfg.Conn, to
			if i == 1 {
				conn, addrs = cfg.Streams, sto
			}
			if err := conn.WriteBatch(batch, addrs); err != nil {
				log.Warn("send failed", "err", err)
			}
			for _, p := range batch {
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
			case session.SessionClosed:
				cfg.Gateway.Release(e.Session)
				log.Info("session closed", "address", netip.AddrFrom4(e.Session.Config().IPv4), "reason", e.Err)
				for k, b := range bridges {
					if k.s == e.Session {
						b.finish(true)
					}
				}
			case session.StreamOpened:
				k := streamKey{e.Session, e.ID}
				if !allow(e.Dst) {
					e.Session.StreamReset(time.Now(), e.ID, wire.CodeUnauthorized)
					continue
				}
				go func(dst netip.AddrPort) {
					conn, err := dial(ctx, dst)
					select {
					case dials <- dialResult{k, conn, err}:
					case <-ctx.Done():
						if conn != nil {
							conn.Close()
						}
					}
				}(e.Dst)
			case session.RelayStreamUpdate:
				k := streamKey{e.Session, e.ID}
				if b := bridges[k]; b != nil {
					b.service(time.Now())
				}
			}
		}
		for _, p, ok := r.PollIP(); ok; _, p, ok = r.PollIP() {
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
		case d := <-dials:
			now := time.Now()
			switch {
			case d.err != nil:
				d.key.s.StreamReset(now, d.key.id, wire.CodeConnectFailed)
			case d.key.s.State() != session.StateActive:
				d.conn.Close()
			default:
				conn, ok := d.conn.(halfCloser)
				if !ok {
					d.conn.Close()
					d.key.s.StreamReset(now, d.key.id, wire.CodeConnectFailed)
					break
				}
				abort := conn.Close
				if tc, ok := d.conn.(*net.TCPConn); ok {
					abort = func() error { abortTCP(tc)(); return nil }
				}
				b := newBridge(d.key.id, d.key.s, conn, func() { abort() })
				bridges[d.key] = b
				b.forget = func() { delete(bridges, d.key) }
				b.start(ctx, bridgeEvents)
				b.service(now)
			}
		case e := <-bridgeEvents:
			e.b.handle(time.Now(), e)
		case <-status:
			now := time.Now()
			for _, s := range r.LiveSessions() {
				lease := netip.AddrFrom4(s.Config().IPv4)
				for _, p := range s.Paths(now) {
					log.Info("path", "session", lease, "id", p.ID, "downlink", p.Primary, "healthy", p.Healthy,
						"flows", p.Flows, "srtt", p.SRTT.Round(100*time.Microsecond), "loss", fmt.Sprintf("%.3f", p.Loss))
				}
			}
		case <-timer.C:
			r.Tick(time.Now())
		}
	}
}
