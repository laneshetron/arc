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
	if _, err := RevokeByDevice(st.Clone(), a.ID, c.ID, false, day.Add(-time.Second)); !errors.Is(err, ErrCoolingOff) {
		t.Fatalf("young device revoked another: %v", err)
	}
	if gone, err := RevokeByDevice(st.Clone(), a.ID, a.ID, false, t0); err != nil || len(gone) != 1 {
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
	if _, err := RevokeByDevice(st.Clone(), root.ID, x.ID, false, day); !errors.Is(err, ErrNoDevice) {
		t.Errorf("revoked another account's device: %v", err)
	}
	if _, err := RevokeByDevice(st.Clone(), root.ID, NewID(), false, day); !errors.Is(err, ErrNoDevice) {
		t.Errorf("revoked a device that never was: %v", err)
	}
	// A device bound to no key, or of an account with manage=no, may not.
	if _, err := RevokeByDevice(st.Clone(), x.ID, x.ID, false, day); !errors.Is(err, ErrNoManage) {
		t.Errorf("legacy device revoked: %v", err)
	}
	st.AccountByID(root.Account).Manage = false
	if _, err := RevokeByDevice(st.Clone(), root.ID, c.ID, false, day); !errors.Is(err, ErrNoManage) {
		t.Errorf("manage=no account's device revoked: %v", err)
	}
	st.AccountByID(root.Account).Manage = true

	// c revokes a and its descendants, softly.
	gone, err := RevokeByDevice(st, c.ID, a.ID, true, day)
	if err != nil || len(gone) != 2 || st.DeviceByID(a.ID) != nil || st.DeviceByID(b.ID) != nil {
		t.Fatalf("revoke a with descendants: %v %v", gone, err)
	}
	for _, tb := range st.Revoked[len(st.Revoked)-2:] {
		if tb.By != c.ID || tb.Rest == "" {
			t.Errorf("tombstone %+v is not restorable", tb)
		}
	}
	// Again: already revoked, nothing to do.
	if gone, err := RevokeByDevice(st, c.ID, a.ID, true, day); err != nil || len(gone) != 0 {
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
	if _, err := RevokeByDevice(st, root.ID, a.ID, true, day); err != nil {
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
	if _, err := RevokeByDevice(st, root.ID, a.ID, false, day); err != nil {
		t.Fatal(err)
	}
	if st.DeviceByID(b.ID) == nil {
		t.Fatal("a plain revocation revoked b")
	}
	gone, err := RevokeByDevice(st, root.ID, a.ID, true, day)
	if err != nil || len(gone) != 1 || gone[0] != b || st.DeviceByID(b.ID) != nil {
		t.Fatalf("cascade after the parent: %v %v", gone, err)
	}
	// An operator revocation's tombstone counts too.
	c := mintAndEnroll(t, st, root, "c", day)
	d := mintAndEnroll(t, st, c, "d", day)
	if _, err := Revoke(st, "alexei/c", day, false); err != nil {
		t.Fatal(err)
	}
	if gone, err := RevokeByDevice(st, root.ID, c.ID, true, day); err != nil || len(gone) != 1 || gone[0].ID != d.ID {
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
	if _, err := RevokeByDevice(st.Clone(), a.ID, a.ID, true, t0); !errors.Is(err, ErrCoolingOff) {
		t.Fatalf("young device revoked its descendants: %v", err)
	}
	if gone, err := RevokeByDevice(st.Clone(), a.ID, a.ID, false, t0); err != nil || len(gone) != 1 {
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
	if _, err := RevokeByDevice(st, root.ID, a.ID, false, day); err != nil {
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
