package accounts

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestRevokeByDevice(t *testing.T) {
	st := &State{}
	root := enrollRoot(t, st, 6)
	a := mintAndEnroll(t, st, root, "a", t0)
	b := mintAndEnroll(t, st, a, "b", t0)
	c := mintAndEnroll(t, st, root, "c", t0)
	day := t0.Add(CoolingOff)

	// Too young to revoke another, but never to revoke itself.
	if _, err := RevokeByDevice(st.Clone(), a.ID, NewID(), c.ID, false, day.Add(-time.Second)); !errors.Is(err, ErrCoolingOff) {
		t.Fatalf("young device revoked another: %v", err)
	}
	if gone, err := RevokeByDevice(st.Clone(), a.ID, NewID(), a.ID, false, t0); err != nil || len(gone) != 1 {
		t.Fatalf("self revocation: %v %v", gone, err)
	}

	// Another account's device, or none, is unknown.
	if _, err := AddAccount(st, "other", false, 0); err != nil {
		t.Fatal(err)
	}
	_, tok, err := AddToken(st, "other", "x", t0)
	if err != nil {
		t.Fatal(err)
	}
	x := st.Devices[len(st.Devices)-1]
	_ = tok
	if _, err := RevokeByDevice(st.Clone(), root.ID, NewID(), x.ID, false, day); !errors.Is(err, ErrNoDevice) {
		t.Errorf("revoked another account's device: %v", err)
	}
	if _, err := RevokeByDevice(st.Clone(), root.ID, NewID(), NewID(), false, day); !errors.Is(err, ErrNoDevice) {
		t.Errorf("revoked a device that never was: %v", err)
	}
	// A device bound to no key, or of an account with manage=no, may not.
	if _, err := RevokeByDevice(st.Clone(), x.ID, NewID(), x.ID, false, day); !errors.Is(err, ErrNoManage) {
		t.Errorf("legacy device revoked: %v", err)
	}
	st.AccountByID(root.Account).Manage = false
	if _, err := RevokeByDevice(st.Clone(), root.ID, NewID(), c.ID, false, day); !errors.Is(err, ErrNoManage) {
		t.Errorf("manage=no account's device revoked: %v", err)
	}
	st.AccountByID(root.Account).Manage = true

	// c revokes a and its descendants, softly.
	gone, err := RevokeByDevice(st, c.ID, NewID(), a.ID, true, day)
	if err != nil || len(gone) != 2 || st.DeviceByID(a.ID) != nil || st.DeviceByID(b.ID) != nil {
		t.Fatalf("revoke a with descendants: %v %v", gone, err)
	}
	for _, tb := range st.Revoked[len(st.Revoked)-2:] {
		if tb.By != c.ID || tb.Rest == "" {
			t.Errorf("tombstone %+v is not restorable", tb)
		}
	}
	// Again: already revoked, nothing to do.
	if gone, err := RevokeByDevice(st, c.ID, NewID(), a.ID, true, day); err != nil || len(gone) != 0 {
		t.Errorf("repeat: %v %v", gone, err)
	}
	if !strings.Contains(List(st), "revoked a") {
		t.Errorf("list omits the restorable device:\n%s", List(st))
	}
}

func TestRestore(t *testing.T) {
	st := &State{}
	root := enrollRoot(t, st, 6)
	a := mintAndEnroll(t, st, root, "a", t0)
	b := mintAndEnroll(t, st, a, "b", t0)
	day := t0.Add(CoolingOff)
	if _, err := RevokeByDevice(st, root.ID, NewID(), a.ID, true, day); err != nil {
		t.Fatal(err)
	}
	// The tombstones survive the file.
	back, err := Parse(st.Marshal(), day)
	if err != nil {
		t.Fatal(err)
	}
	st = back
	if _, err := Restore(st, "alexei/a", day.Add(TombstoneLife)); err == nil {
		t.Error("restored past the tombstone's life")
	}
	if _, err := Restore(st, "alexei/a", day.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	got := st.DeviceByID(a.ID)
	if got == nil || got.TokenHash != a.TokenHash || string(got.Key) != string(a.Key) || len(got.Lineage) != 1 || !got.Created.Equal(a.Created) {
		t.Fatalf("restored %+v, want %+v", got, a)
	}
	if _, err := Restore(st, "alexei/a", day.Add(time.Hour)); err == nil {
		t.Error("restored twice")
	}
	// A name taken since cannot be restored over.
	if _, _, err := AddToken(st, "alexei", "b", day); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(st, "alexei/b", day.Add(time.Hour)); err == nil {
		t.Error("restored over a device of the same name")
	}
	_ = b
	// Operator revocations are final.
	if _, err := Revoke(st, "alexei/a", day, false); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(st, "alexei/a", day.Add(time.Hour)); err == nil {
		t.Error("restored an operator revocation")
	}
}

// TestRevokeCascadeAfterParent: a descendant revocation still reaches the
// invitees of a device already revoked on its own.
func TestRevokeCascadeAfterParent(t *testing.T) {
	st := &State{}
	root := enrollRoot(t, st, 6)
	a := mintAndEnroll(t, st, root, "a", t0)
	b := mintAndEnroll(t, st, a, "b", t0)
	day := t0.Add(CoolingOff)
	if _, err := RevokeByDevice(st, root.ID, NewID(), a.ID, false, day); err != nil {
		t.Fatal(err)
	}
	if st.DeviceByID(b.ID) == nil {
		t.Fatal("a plain revocation revoked b")
	}
	gone, err := RevokeByDevice(st, root.ID, NewID(), a.ID, true, day)
	if err != nil || len(gone) != 1 || gone[0] != b || st.DeviceByID(b.ID) != nil {
		t.Fatalf("cascade after the parent: %v %v", gone, err)
	}
	// An operator revocation's tombstone counts too.
	c := mintAndEnroll(t, st, root, "c", day)
	d := mintAndEnroll(t, st, c, "d", day)
	if _, err := Revoke(st, "alexei/c", day, false); err != nil {
		t.Fatal(err)
	}
	if gone, err := RevokeByDevice(st, root.ID, NewID(), c.ID, true, day); err != nil || len(gone) != 1 || gone[0].ID != d.ID {
		t.Fatalf("cascade after an operator revocation: %v %v", gone, err)
	}
}

// TestRevokeCoolingOffCascade: a young device may revoke itself, but not
// take its descendants with it.
func TestRevokeCoolingOffCascade(t *testing.T) {
	st := &State{}
	root := enrollRoot(t, st, 6)
	a := mintAndEnroll(t, st, root, "a", t0)
	mintAndEnroll(t, st, a, "b", t0)
	if _, err := RevokeByDevice(st.Clone(), a.ID, NewID(), a.ID, true, t0); !errors.Is(err, ErrCoolingOff) {
		t.Fatalf("young device revoked its descendants: %v", err)
	}
	if gone, err := RevokeByDevice(st.Clone(), a.ID, NewID(), a.ID, false, t0); err != nil || len(gone) != 1 {
		t.Fatalf("young device revoking itself: %v %v", gone, err)
	}
}

// TestRotateEndsRestore: a rotation makes earlier revocations by devices
// final, so restore cannot bring back a pre-rotation device.
func TestRotateEndsRestore(t *testing.T) {
	st := &State{}
	root := enrollRoot(t, st, 6)
	a := mintAndEnroll(t, st, root, "a", t0)
	day := t0.Add(CoolingOff)
	if _, err := RevokeByDevice(st, root.ID, NewID(), a.ID, false, day); err != nil {
		t.Fatal(err)
	}
	if _, err := Rotate(st, "alexei", day); err != nil {
		t.Fatal(err)
	}
	if _, err := Restore(st, "alexei/a", day.Add(time.Hour)); err == nil {
		t.Error("restored a device revoked before the rotation")
	}
	// Every tombstone keeps the revoked token's hash, through the file.
	back, err := Parse(st.Marshal(), day)
	if err != nil {
		t.Fatal(err)
	}
	for _, tb := range back.Revoked {
		if tb.ID == a.ID && tb.TokenHash != a.TokenHash {
			t.Errorf("tombstone token %x, want %x", tb.TokenHash, a.TokenHash)
		}
	}
}

// TestRevokeRequestDurable: a request's tombstones record it, through
// the file and a restore, so its repeat revokes nothing.
func TestRevokeRequestDurable(t *testing.T) {
	st := &State{}
	root := enrollRoot(t, st, 6)
	a := mintAndEnroll(t, st, root, "a", t0)
	day := t0.Add(CoolingOff)
	req := NewID()
	if _, err := RevokeByDevice(st, root.ID, req, a.ID, false, day); err != nil {
		t.Fatal(err)
	}
	reload := func() {
		t.Helper()
		back, err := Parse(st.Marshal(), day)
		if err != nil {
			t.Fatal(err)
		}
		st = back
	}
	reload()
	if _, err := Restore(st, "alexei/a", day); err != nil {
		t.Fatal(err)
	}
	reload()
	if gone, err := RevokeByDevice(st, root.ID, req, a.ID, false, day); err != nil || len(gone) != 0 || st.DeviceByID(a.ID) == nil {
		t.Fatalf("repeat after restore: %v %v", gone, err)
	}
	// A new request revokes it again, and that one can be restored.
	req2 := NewID()
	if gone, err := RevokeByDevice(st, root.ID, req2, a.ID, false, day); err != nil || len(gone) != 1 {
		t.Fatalf("new request: %v %v", gone, err)
	}
	reload()
	if _, err := Restore(st, "alexei/a", day); err != nil {
		t.Fatalf("second restore: %v", err)
	}
	reload()
	// Both requests stay recorded: neither's repeat revokes it again.
	for i, r := range []ID{req, req2} {
		if gone, err := RevokeByDevice(st, root.ID, r, a.ID, false, day); err != nil || len(gone) != 0 || st.DeviceByID(a.ID) == nil {
			t.Fatalf("repeat of request %d after the second restore: %v %v", i+1, gone, err)
		}
	}
	if err := st.Validate(); err != nil {
		t.Fatal(err)
	}
	// They last as long as their tombstones, then are pruned.
	st.Prune(day.Add(TombstoneLife))
	if len(st.Revoked) != 0 {
		t.Errorf("%d tombstones past their life", len(st.Revoked))
	}
}
