package gateway

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
)

func storeGateway(t *testing.T, st *accounts.State, gate func() bool) *Gateway {
	t.Helper()
	g, err := New(Config{Network: netip.MustParsePrefix("10.77.0.1/16"), TunMTU: 1280, Gate: gate})
	if err != nil {
		t.Fatal(err)
	}
	g.Apply(st)
	return g
}

func twoAccounts(t *testing.T) (*accounts.State, []byte, []byte) {
	t.Helper()
	st := &accounts.State{}
	accounts.AddAccount(st, "a", true, 0)
	accounts.AddAccount(st, "b", false, 0)
	_, ta, err := accounts.AddToken(st, "a", "laptop", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	_, tb, _ := accounts.AddToken(st, "b", "phone", time.Now())
	return st, ta, tb
}

// TestApplyKeepsAccountIdentity: a lease granted before an update keeps
// its account through it, so refreshes and isolation still hold, and the
// account's new name and policy apply to it.
func TestApplyKeepsAccountIdentity(t *testing.T) {
	st, ta, tb := twoAccounts(t)
	g := storeGateway(t, st, nil)
	r, err := g.Authorize(ta, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := netip.AddrFrom4(r.IPv4)
	b := authorize(t, g, string(tb))
	if g.DeviceName(a) != "laptop" {
		t.Errorf("device %q", g.DeviceName(a))
	}

	next := st.Clone()
	acct := next.AccountByName("a")
	acct.Name, acct.RelayAccess = "renamed", false
	accounts.AddToken(next, "renamed", "desktop", time.Now())
	g.Apply(next)
	if _, err := g.Authorize(ta, nil, &r); err != nil {
		t.Errorf("refresh after an update: %v", err)
	}
	if g.AccountName(a) != "renamed" || g.allowTunnel(a, netip.MustParseAddr("10.77.0.1")) {
		t.Errorf("lease kept the old account's name or policy: %q", g.AccountName(a))
	}
	if g.allowForward(a, packet(a, b)) {
		t.Error("accounts not isolated after an update")
	}
	if len(g.Tokens()) != 0 {
		t.Error("store accounts exposed plaintext tokens")
	}
}

// TestApplyRevokes: a device removed by an update loses its lease: no
// refresh, no traffic either way, and a session not yet bound is refused.
func TestApplyRevokes(t *testing.T) {
	st, ta, tb := twoAccounts(t)
	g := storeGateway(t, st, nil)
	r, _ := g.Authorize(ta, nil, nil)
	a := netip.AddrFrom4(r.IPv4)
	b := authorize(t, g, string(tb))

	next := st.Clone()
	if _, err := accounts.Revoke(next, "a/laptop", time.Now()); err != nil {
		t.Fatal(err)
	}
	g.Apply(next)
	if _, err := g.Authorize(ta, nil, nil); !errors.Is(err, ErrBadCredential) {
		t.Errorf("revoked token authorized: %v", err)
	}
	if _, err := g.Authorize(ta, nil, &r); err == nil {
		t.Error("revoked token refreshed")
	}
	if g.Lookup(packet(b, a)) != nil || g.allowForward(b, packet(b, a)) {
		t.Error("traffic still reaches the revoked lease")
	}
	if !g.isRevoked(a) || g.isRevoked(b) {
		t.Error("wrong leases revoked")
	}
}

func TestKeyBinding(t *testing.T) {
	st, ta, _ := twoAccounts(t)
	key := make([]byte, 32)
	key[0] = 7
	st.Devices[0].Key = key
	g := storeGateway(t, st, nil)
	if _, err := g.Authorize(ta, make([]byte, 32), nil); !errors.Is(err, ErrWrongKey) {
		t.Errorf("token from another key: %v", err)
	}
	if _, err := g.Authorize(ta, key, nil); err != nil {
		t.Errorf("token from its key: %v", err)
	}
}

func TestGate(t *testing.T) {
	st, ta, _ := twoAccounts(t)
	serving := false
	g := storeGateway(t, st, func() bool { return serving })
	if _, err := g.Authorize(ta, nil, nil); !errors.Is(err, ErrNotServing) {
		t.Errorf("authorized while not serving: %v", err)
	}
	serving = true
	if _, err := g.Authorize(ta, nil, nil); err != nil {
		t.Error(err)
	}
}
