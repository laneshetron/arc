package accounts

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testInviteKey = bytes.Repeat([]byte{0x42}, InviteKeySize)

// enrollRoot adds an account and a key-bound device enrolled by an
// operator invite.
func enrollRoot(t *testing.T, st *State, maxDevices int) *Device {
	t.Helper()
	if _, err := AddAccount(st, "alexei", false, maxDevices); err != nil {
		t.Fatal(err)
	}
	i, secret, err := AddInvite(st, "alexei", time.Hour, t0)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Redeem(st, i.ID, secret[:], newTestToken(), bytes.Repeat([]byte{1}, 32), "root", t0)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

var tokenSeq int

func newTestToken() []byte {
	tokenSeq++
	return []byte(fmt.Sprintf("token-%040d", tokenSeq))
}

// mintAndEnroll has minter mint an invite, at the next generation, and a
// new device redeem it.
func mintAndEnroll(t *testing.T, st *State, minter *Device, name string, now time.Time) *Device {
	t.Helper()
	i, secret, minted, err := MintInvite(st, testInviteKey, minter.ID, NewID(), now)
	if err != nil || !minted {
		t.Fatalf("%s mints: %v", minter.Name, err)
	}
	st.Generation++ // as Writer.Commit does
	d, err := Redeem(st, i.ID, secret[:], newTestToken(), bytes.Repeat([]byte{2}, 32), name, now)
	if err != nil {
		t.Fatalf("%s enrolls: %v", name, err)
	}
	return d
}

func TestMintInvite(t *testing.T) {
	st := &State{Generation: 10}
	root := enrollRoot(t, st, 5)
	req := NewID()
	i, secret, minted, err := MintInvite(st, testInviteKey, root.ID, req, t0)
	if err != nil || !minted || i.By != root.ID || i.Request != req || i.Gen != 11 || !i.Expires.Equal(t0.Add(MintedInviteTTL)) {
		t.Fatalf("mint: %+v %v %v", i, minted, err)
	}
	st.Generation++

	// The record keeps no secret, and survives the file.
	back, err := Parse(st.Marshal(), t0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(st.Marshal()), fmt.Sprintf("%x", secret)) {
		t.Error("the secret is in the file")
	}
	// A repeat is the same invite, recomputed from the record.
	i2, secret2, minted, err := MintInvite(back, testInviteKey, root.ID, req, t0.Add(time.Hour))
	if err != nil || minted || i2.ID != i.ID || secret2 != secret {
		t.Fatalf("repeat: %+v %v %v", i2, minted, err)
	}
	if _, err := back.CheckInvite(i.ID, secret[:]); err != nil {
		t.Errorf("the derived secret does not match the record: %v", err)
	}
	// With another invite key, the repeat cannot be recomputed.
	if _, _, _, err := MintInvite(back, bytes.Repeat([]byte{7}, InviteKeySize), root.ID, req, t0); !errors.Is(err, ErrInviteKeyChanged) {
		t.Errorf("another key: %v", err)
	}
	// Past its expiry, the repeat is refused, never reissued.
	if _, _, _, err := MintInvite(back, testInviteKey, root.ID, req, t0.Add(MintedInviteTTL)); !errors.Is(err, ErrInviteExpired) {
		t.Errorf("repeat past expiry: %v", err)
	}
	// Once the record is pruned, the same request mints afresh, at a new
	// generation: a different invite, so the expired one stays dead.
	late := t0.Add(MintedInviteTTL + TombstoneLife + time.Hour)
	back.Prune(late)
	back.Generation += 5
	i3, secret3, minted, err := MintInvite(back, testInviteKey, root.ID, req, late)
	if err != nil || !minted || i3.ID == i.ID || secret3 == secret {
		t.Fatalf("after the record is gone: %+v %v %v", i3, minted, err)
	}
}

func TestMintRefusals(t *testing.T) {
	st := &State{}
	root := enrollRoot(t, st, 3)

	// Two outstanding invites, then no more.
	for range MaxOutstanding {
		if _, _, _, err := MintInvite(st, testInviteKey, root.ID, NewID(), t0); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, _, err := MintInvite(st, testInviteKey, root.ID, NewID(), t0); !errors.Is(err, ErrInviteCap) {
		t.Errorf("third outstanding: %v", err)
	}
	// Expired ones no longer count.
	if _, _, _, err := MintInvite(st, testInviteKey, root.ID, NewID(), t0.Add(MintedInviteTTL)); err != nil {
		t.Errorf("after the others expired: %v", err)
	}

	// At the device cap.
	st2 := &State{}
	r2 := enrollRoot(t, st2, 2)
	mintAndEnroll(t, st2, r2, "phone", t0)
	if _, _, _, err := MintInvite(st2, testInviteKey, r2.ID, NewID(), t0); !errors.Is(err, ErrDeviceCap) {
		t.Errorf("at the cap: %v", err)
	}

	// A legacy device, bound to no key, may not mint, whatever the policy.
	_, tok, err := AddToken(st, "alexei", "legacy", t0)
	if err != nil {
		t.Fatal(err)
	}
	var legacy *Device
	for _, d := range st.Devices {
		if d.TokenHash == TokenHash(tok) {
			legacy = d
		}
	}
	if _, _, _, err := MintInvite(st, testInviteKey, legacy.ID, NewID(), t0); !errors.Is(err, ErrNotPermitted) {
		t.Errorf("legacy device: %v", err)
	}
	// Nor may an account's devices with invites=no.
	st.AccountByName("alexei").Invites = false
	if _, _, _, err := MintInvite(st, testInviteKey, root.ID, NewID(), t0.Add(48*time.Hour)); !errors.Is(err, ErrNotPermitted) {
		t.Errorf("invites=no: %v", err)
	}
}

// TestLineage: each device minted for carries its minter's lineage and
// the minter; a device with a 6-entry lineage may mint, and its child
// enrolls with 7; a device with 7 is refused.
func TestLineage(t *testing.T) {
	st := &State{}
	d := enrollRoot(t, st, MaxDevicesLimit)
	chain := []*Device{d}
	for n := 1; n <= MaxLineage; n++ {
		now := t0.Add(time.Duration(n) * time.Minute)
		d = mintAndEnroll(t, st, d, fmt.Sprintf("gen%d", n), now)
		if len(d.Lineage) != n || d.Lineage[n-1] != chain[n-1].ID || d.Lineage[0] != chain[0].ID {
			t.Fatalf("gen%d lineage: %v", n, d.Lineage)
		}
		chain = append(chain, d)
	}
	if _, _, _, err := MintInvite(st, testInviteKey, d.ID, NewID(), t0.Add(time.Hour)); !errors.Is(err, ErrLineageFull) {
		t.Errorf("a device with %d lineage entries minted: %v", len(d.Lineage), err)
	}
	if _, err := Parse(st.Marshal(), t0); err != nil {
		t.Errorf("a full chain does not round-trip: %v", err)
	}
}

// TestRevokeDescendants: revoke -descendants reaches every device under
// the revoked one by lineage alone, after the invites linking them have
// expired and been pruned and a device between them was revoked.
func TestRevokeDescendants(t *testing.T) {
	st := &State{}
	root := enrollRoot(t, st, 6)
	a := mintAndEnroll(t, st, root, "a", t0)
	b := mintAndEnroll(t, st, a, "b", t0)
	c := mintAndEnroll(t, st, b, "c", t0)
	other := mintAndEnroll(t, st, root, "other", t0)
	_ = other
	// The invites expire and their records are pruned; then b goes.
	late := t0.Add(MintedInviteTTL + TombstoneLife + time.Hour)
	st.Prune(late)
	if len(st.Invites) != 0 {
		t.Fatalf("invites not pruned: %d", len(st.Invites))
	}
	if _, err := Revoke(st, "alexei/b", late, false); err != nil {
		t.Fatal(err)
	}
	if st.DeviceByID(c.ID) == nil {
		t.Fatal("revoking b alone revoked c")
	}
	out, err := Revoke(st, "alexei/a", late, true)
	if err != nil {
		t.Fatal(err)
	}
	if st.DeviceByID(a.ID) != nil || st.DeviceByID(c.ID) != nil {
		t.Errorf("a's descendants survive:\n%s", out)
	}
	if st.DeviceByID(root.ID) == nil || st.DeviceByID(other.ID) == nil {
		t.Errorf("revoked beyond a's descendants:\n%s", out)
	}
	if !strings.Contains(out, "alexei/c") {
		t.Errorf("output does not name c:\n%s", out)
	}
}

func TestRotate(t *testing.T) {
	st := &State{}
	root := enrollRoot(t, st, 5)
	mintAndEnroll(t, st, root, "phone", t0)
	if _, _, _, err := MintInvite(st, testInviteKey, root.ID, NewID(), t0); err != nil {
		t.Fatal(err)
	}
	if _, err := AddAccount(st, "bob", false, 2); err != nil {
		t.Fatal(err)
	}
	bobInvite, _, _ := AddInvite(st, "bob", time.Hour, t0)
	st.AccountByName("alexei").MaxDevices = 4
	if _, err := Rotate(st, "alexei", t0); err != nil {
		t.Fatal(err)
	}
	a := st.AccountByName("alexei")
	if a == nil || a.MaxDevices != 4 || len(st.DevicesOf(a.ID)) != 0 {
		t.Fatalf("after rotate: %+v, %d devices", a, len(st.DevicesOf(a.ID)))
	}
	for _, i := range st.Invites {
		if i.Account == a.ID {
			t.Error("an invite of the rotated account survives")
		}
	}
	if st.InviteByID(bobInvite.ID) == nil {
		t.Error("rotate cancelled another account's invite")
	}
	if len(st.Revoked) != 2 {
		t.Errorf("%d tombstones, want 2", len(st.Revoked))
	}
}

// A minted invite's record must survive the store: a writer that reloads
// it (on restart or takeover) must parse what the last one wrote.
func TestMintRecordsReload(t *testing.T) {
	ctx := context.Background()
	store := FileStore{Path: filepath.Join(t.TempDir(), "accounts")}
	c := &clock{t: t0}
	tokens := filepath.Join(t.TempDir(), "lease-token")
	var root *Device
	w := newWriter(t, store, "a", c)
	w.TokenFile = tokens
	w.Seed = func() (*State, error) { st := &State{}; root = enrollRoot(t, st, 5); return st, nil }
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	mint := func(request ID) error {
		return w.Commit(ctx, func(st *State) error {
			_, _, _, err := MintInvite(st, testInviteKey, root.ID, request, c.Now())
			return err
		})
	}
	if err := mint(ID{}); !errors.Is(err, ErrNotPermitted) {
		t.Fatalf("zero request: %v", err)
	}
	// Records the file cannot hold are refused before they are written.
	err := w.Commit(ctx, func(st *State) error {
		st.Invites = append(st.Invites, &Invite{ID: NewID(), Account: root.Account, By: root.ID,
			Expires: c.Now().Add(time.Hour)})
		return nil
	})
	if err == nil {
		t.Fatal("committed a minted invite without its request")
	}
	req := NewID()
	if err := mint(req); err != nil {
		t.Fatal(err)
	}
	w2 := newWriter(t, store, "a", c)
	w2.TokenFile = tokens
	if err := w2.Acquire(ctx); err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if i := w2.State().MintedBy(root.ID, req); i == nil {
		t.Fatalf("reloaded state lacks the invite: %s", w2.State().Marshal())
	}
}
