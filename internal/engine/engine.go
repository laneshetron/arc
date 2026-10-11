// Package engine runs ARC sessions against real sockets, TUN devices, and
// the wall clock. Each engine is one event loop goroutine that owns its
// session state machine; reader goroutines feed it batches of packets over
// channels, so the state machines never need locks.
package engine

import (
	"context"
	"net/netip"
	"time"

	"github.com/laneshetron/arc/internal/carrier/udp"
)

// PacketDevice is a source and sink of IP packets, normally a TUN device.
// Packets returned by Read are valid only until the next Read.
type PacketDevice interface {
	Read() ([][]byte, error)
	Write(pkts [][]byte) error
}

// DatagramConn is a datagram carrier, normally a *udp.Conn.
type DatagramConn interface {
	ReadBatch(bufs [][]byte, sizes []int, addrs []netip.AddrPort) (int, error)
	WriteBatch(pkts [][]byte, addrs []netip.AddrPort) error
}

const readBatch = 64

type datagrams struct {
	carrier int // index of the carrier the batch arrived on
	pkts    [][]byte
	from    []netip.AddrPort
}

// readDatagrams copies batches from conn into out until reading fails.
func readDatagrams(ctx context.Context, carrier int, conn DatagramConn, out chan<- datagrams, errc chan<- error) {
	bufs := make([][]byte, readBatch)
	for i := range bufs {
		bufs[i] = make([]byte, udp.MaxDatagram)
	}
	sizes, addrs := make([]int, readBatch), make([]netip.AddrPort, readBatch)
	for {
		n, err := conn.ReadBatch(bufs, sizes, addrs)
		if n > 0 {
			d := datagrams{carrier: carrier, pkts: make([][]byte, n), from: make([]netip.AddrPort, n)}
			for i := range n {
				d.pkts[i] = append([]byte(nil), bufs[i][:sizes[i]]...)
				d.from[i] = addrs[i]
			}
			select {
			case out <- d:
			case <-ctx.Done():
				return
			}
		}
		if err != nil {
			report(ctx, errc, err)
			return
		}
	}
}

// readPackets copies batches from dev into out until reading fails.
func readPackets(ctx context.Context, dev PacketDevice, out chan<- [][]byte, errc chan<- error) {
	for {
		pkts, err := dev.Read()
		if len(pkts) > 0 {
			owned := make([][]byte, len(pkts))
			for i, p := range pkts {
				owned[i] = append([]byte(nil), p...)
			}
			select {
			case out <- owned:
			case <-ctx.Done():
				return
			}
		}
		if err != nil {
			report(ctx, errc, err)
			return
		}
	}
}

func report(ctx context.Context, errc chan<- error, err error) {
	if ctx.Err() != nil {
		return // shutting down; the closed socket or device is expected
	}
	select {
	case errc <- err:
	default:
	}
}

// resetTimer arms t for deadline, or disarms it for a zero deadline.
func resetTimer(t *time.Timer, deadline time.Time) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
	if deadline.IsZero() {
		return
	}
	t.Reset(max(time.Until(deadline), 0))
}
