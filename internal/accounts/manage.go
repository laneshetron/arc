package accounts

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Devices managing devices (self-service-accounts.md §3.8).

// CoolingOff is how long a device must have been enrolled before it may
// revoke another device; it may always revoke itself.
const CoolingOff = 24 * time.Hour

var (
	ErrNoManage   = errors.New("accounts: this device may not manage devices")
	ErrCoolingOff = fmt.Errorf("accounts: a device may revoke others only once enrolled for %d hours", int(CoolingOff.Hours()))
	ErrNoDevice   = errors.New("accounts: the account has no such device")
)

// MayManage reports whether d may list and revoke its account's devices:
// it is bound to a key and its account allows it.
func (s *State) MayManage(d *Device) bool {
	a := s.AccountByID(d.Account)
	return d.Bound() && a != nil && a.Manage
}

// RevokeByDevice has the device by revoke target, a device of its own
// account, and with descendants every device whose lineage holds target.
// The revocations are soft: each tombstone keeps by and the revoked
// record, so the operator can restore it (Restore) while the tombstone
// lasts. A target already revoked is no error, and revokes nothing. It
// returns the devices revoked.
func RevokeByDevice(st *State, by, target ID, descendants bool, now time.Time) ([]*Device, error) {
	d := st.DeviceByID(by)
	if d == nil || !st.MayManage(d) {
		return nil, ErrNoManage
	}
	t := st.DeviceByID(target)
	if t == nil {
		if slices.ContainsFunc(st.Revoked, func(x *Tombstone) bool { return x.ID == target }) {
			return nil, nil
		}
		return nil, ErrNoDevice
	}
	switch {
	case t.Account != d.Account:
		return nil, ErrNoDevice
	case t != d && now.Sub(d.Created) < CoolingOff:
		return nil, ErrCoolingOff
	}
	gone := []*Device{t}
	if descendants {
		for _, x := range st.Devices {
			if slices.Contains(x.Lineage, t.ID) {
				gone = append(gone, x)
			}
		}
	}
	for _, x := range gone {
		st.revoke(x, now, by)
	}
	return gone, nil
}

// restorable returns the tombstone of a device of account named name
// that a device revoked, and the device's record, or nil.
func (st *State) restorable(account ID, name string, now time.Time) (*Tombstone, *Device) {
	for _, t := range st.Revoked {
		if t.By.IsZero() || t.Rest == "" || !now.Before(t.Until) {
			continue
		}
		if d, err := parseDevice(t.Rest); err == nil && d.Account == account && d.Name == name {
			return t, d
		}
	}
	return nil, nil
}

// Restore reinstates ACCOUNT/DEVICE, revoked by another device within
// TombstoneLife, with its original ID, token hash and key (§3.7). Its
// invites, cancelled with it, stay cancelled. Operator revocations are
// final.
func Restore(st *State, target string, now time.Time) (string, error) {
	account, name, ok := strings.Cut(target, "/")
	if !ok {
		return "", fmt.Errorf("want ACCOUNT/DEVICE, not %q", target)
	}
	a := st.AccountByName(account)
	if a == nil {
		return "", fmt.Errorf("no account %s", account)
	}
	t, d := st.restorable(a.ID, name, now)
	switch {
	case t == nil:
		return "", fmt.Errorf("account %s has no device %s revoked by a device in the last %v (operator revocations are final)", account, name, TombstoneLife)
	case st.device(a.ID, name) != nil:
		return "", fmt.Errorf("account %s has another device named %s now; revoke or rename it first", account, name)
	case len(st.DevicesOf(a.ID)) >= a.MaxDevices:
		return "", fmt.Errorf("account %s is at its device cap (%d)", account, a.MaxDevices)
	}
	st.Revoked = slices.DeleteFunc(st.Revoked, func(x *Tombstone) bool { return x == t })
	st.Devices = append(st.Devices, d)
	return fmt.Sprintf("restored %s/%s\n", account, name), st.Validate()
}
