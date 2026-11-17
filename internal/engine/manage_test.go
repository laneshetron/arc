package engine

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
	"github.com/laneshetron/arc/internal/carrier/udp"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// TestRevokeFromAnotherDevice: while the laptop is connected, the desktop
// lists the account's devices and revokes it; the laptop's session closes
// with REVOKED, and its client stops instead of reconnecting.
func TestRevokeFromAnotherDevice(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	w := &accounts.Writer{Store: accounts.FileStore{Path: filepath.Join(t.TempDir(), "accounts")}, Holder: "relay"}
	relayKey, _ := crypto.GenerateStaticKey(nil)
	relay, _ := mintRelay(t, ctx, w, relayKey)
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	type device struct {
		key   crypto.StaticKey
		token []byte
	}
	enrolled := time.Now().Add(-accounts.CoolingOff - time.Hour) // past the cooling-off
	devices := map[string]*device{}
	if err := w.Commit(ctx, func(st *accounts.State) error {
		if _, err := accounts.AddAccount(st, "alexei", false, 0); err != nil {
			return err
		}
		for _, name := range []string{"laptop", "desktop"} {
			i, secret, err := accounts.AddInvite(st, "alexei", time.Hour, enrolled)
			if err != nil {
				return err
			}
			d := &device{token: accounts.NewToken()}
			d.key, _ = crypto.GenerateStaticKey(nil)
			if _, err := accounts.Redeem(st, i.ID, secret[:], d.token, d.key.Public[:], name, enrolled); err != nil {
				return err
			}
			devices[name] = d
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	client := func(d *device, cfg ClientConfig) <-chan error {
		conn, err := udp.Listen(netip.MustParseAddrPort("127.0.0.1:0"), udp.Options{})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { conn.Close() })
		tun := newMemTUN()
		t.Cleanup(func() { tun.Close() })
		cfg.Session = session.ClientConfig{Static: d.key, RelayPublic: relayKey.Public, Credential: d.token}
		cfg.Relay, cfg.Carriers, cfg.TUN, cfg.ReconnectDelay = relay.LocalAddr(), []Carrier{{Name: "lo", Conn: conn}}, tun, 50*time.Millisecond
		done := make(chan error, 1)
		go func() { done <- RunClient(ctx, cfg) }()
		return done
	}

	up := make(chan wire.AuthResult, 1)
	laptop := client(devices["laptop"], ClientConfig{OnEstablished: func(r wire.AuthResult) error {
		select {
		case up <- r:
		default:
		}
		return nil
	}})
	if r := wait(t, up, "the laptop's session"); r.Features&wire.FeatureDevices == 0 {
		t.Fatalf("the laptop may not manage devices: %#x", r.Features)
	}

	var listed wire.Devices
	var target [8]byte
	listID, revokeID := [8]byte{1}, [8]byte{2}
	desktop := client(devices["desktop"], ClientConfig{Request: &Request{
		Send: func(c *session.Client) error {
			if target == ([8]byte{}) {
				return c.RequestDevices(listID)
			}
			return c.RequestRevoke(revokeID, target, false)
		},
		Answer: func(e session.ClientEvent) (bool, error) {
			switch a := e.(type) {
			case session.DevicesAnswer:
				listed = a.Devices
				for _, d := range a.Devices.Devices {
					if d.Name == "laptop" {
						target = d.ID
					}
				}
				return target != ([8]byte{}), nil
			case session.RevokeAnswer:
				if a.Status != 0 {
					return false, errors.New("revocation refused")
				}
				return false, errStop
			}
			return true, nil
		},
		Repeat: 100 * time.Millisecond,
	}})
	if err := wait(t, desktop, "the desktop"); !errors.Is(err, errStop) {
		t.Fatalf("desktop: %v (listed %+v)", err, listed)
	}
	if len(listed.Devices) != 2 {
		t.Errorf("listed %+v", listed)
	}
	for _, d := range listed.Devices {
		if d.Name == "laptop" && d.LastSeen == 0 {
			t.Error("the connected laptop was never seen")
		}
	}
	if err := wait(t, laptop, "the revoked laptop"); !errors.Is(err, session.ErrRevoked) {
		t.Fatalf("laptop ended with %v, want ErrRevoked", err)
	}
}
