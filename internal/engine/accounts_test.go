package engine

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/gateway"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// TestAccountIsolation runs a relay with two accounts and three clients
// over loopback: a1 and a2 belong to account a (relay access), b to
// account b. Packets the relay writes to its TUN stand for what the
// kernel would route back into the TUN, so the test plays the kernel by
// feeding them back.
func TestAccountIsolation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loop := netip.MustParseAddrPort("127.0.0.1:0")
	relayKey, _ := crypto.GenerateStaticKey(nil)
	gw, err := gateway.New(gateway.Config{
		Network: netip.MustParsePrefix("10.77.0.1/24"), TunMTU: 1280, Accounts: []gateway.Account{
			{Name: "a", Tokens: [][]byte{[]byte("a1"), []byte("a2")}, RelayAccess: true},
			{Name: "b", Tokens: [][]byte{[]byte("b1")}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	relayConn, err := udp.Listen(loop, udp.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer relayConn.Close()
	relayTUN := newMemTUN()
	defer relayTUN.Close()
	go RunRelay(ctx, RelayConfig{
		Session: session.RelayConfig{Static: relayKey, ResetSecret: [32]byte{1}},
		Conn:    relayConn, TUN: relayTUN, Gateway: gw,
	})

	type client struct {
		tun   *memTUN
		lease netip.Addr
	}
	start := func(token string) client {
		t.Helper()
		key, _ := crypto.GenerateStaticKey(nil)
		conn, err := udp.Listen(loop, udp.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		tun := newMemTUN()
		t.Cleanup(tun.Close)
		established := make(chan wire.AuthResult, 1)
		go RunClient(ctx, ClientConfig{
			Session: session.ClientConfig{Static: key, RelayPublic: relayKey.Public, Credential: []byte(token)},
			Relay:   relayConn.LocalAddr(), Carriers: []Carrier{{Name: "lo", Conn: conn}}, TUN: tun,
			OnEstablished: func(r wire.AuthResult) error { established <- r; return nil },
		})
		select {
		case r := <-established:
			return client{tun, netip.AddrFrom4(r.IPv4)}
		case <-time.After(5 * time.Second):
			t.Fatalf("client %s not established", token)
			return client{}
		}
	}
	a1, a2, b := start("a1"), start("a2"), start("b1")
	relay := netip.MustParseAddr("10.77.0.1")

	// nothing fails if any TUN sees a packet within a short wait.
	nothing := func(what string) {
		t.Helper()
		select {
		case p := <-relayTUN.out:
			t.Fatalf("%s: relay wrote %v -> %v to its TUN", what, netip.AddrFrom4([4]byte(p[12:16])), netip.AddrFrom4([4]byte(p[16:20])))
		case <-a1.tun.out:
			t.Fatalf("%s: a1 received a packet", what)
		case <-a2.tun.out:
			t.Fatalf("%s: a2 received a packet", what)
		case <-b.tun.out:
			t.Fatalf("%s: b received a packet", what)
		case <-time.After(300 * time.Millisecond):
		}
	}

	// Same account: forwarded to the TUN, and delivered once the kernel
	// routes it back.
	p := ipv4(a1.lease, a2.lease, 100, 1)
	a1.tun.in <- [][]byte{p}
	if got := recv(t, relayTUN.out); !bytes.Equal(got, p) {
		t.Fatal("same-account packet corrupted")
	}
	relayTUN.in <- [][]byte{p}
	if got := recv(t, a2.tun.out); !bytes.Equal(got, p) {
		t.Fatal("same-account packet not delivered")
	}

	// Other account, either direction: not even written to the TUN.
	a1.tun.in <- [][]byte{ipv4(a1.lease, b.lease, 100, 2)}
	b.tun.in <- [][]byte{ipv4(b.lease, a2.lease, 100, 3)}
	nothing("cross-account uplink")

	// Should the kernel route one back anyway (another path into the TUN,
	// a stale route), delivery refuses it too.
	relayTUN.in <- [][]byte{ipv4(a1.lease, b.lease, 100, 4), ipv4(b.lease, a1.lease, 100, 5)}
	nothing("cross-account downlink")

	// The relay's own address: only for relay access, but its packets
	// (replies, ICMP errors) reach every client.
	p = ipv4(a1.lease, relay, 100, 6)
	a1.tun.in <- [][]byte{p}
	if got := recv(t, relayTUN.out); !bytes.Equal(got, p) {
		t.Fatal("relay-access client could not reach the relay")
	}
	b.tun.in <- [][]byte{ipv4(b.lease, relay, 100, 7)}
	nothing("relay without relay access")
	p = ipv4(relay, b.lease, 100, 8)
	relayTUN.in <- [][]byte{p}
	if got := recv(t, b.tun.out); !bytes.Equal(got, p) {
		t.Fatal("relay's packet did not reach a client without relay access")
	}

	// The internet works for both accounts.
	internet := netip.MustParseAddr("198.51.100.7")
	for _, c := range []client{a1, b} {
		p := ipv4(c.lease, internet, 100, 9)
		c.tun.in <- [][]byte{p}
		if got := recv(t, relayTUN.out); !bytes.Equal(got, p) {
			t.Fatalf("%v could not reach the internet", c.lease)
		}
	}
}
