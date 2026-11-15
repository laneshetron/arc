package accounts

import (
	"fmt"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
)

// Operator operations (self-service-accounts.md §3.2, §3.7). Each changes
// a State inside a transaction (Writer.Commit) and returns what to tell
// the operator.

// AddAccount creates an account with no devices.
func AddAccount(st *State, name string, relay bool, maxDevices int) (string, error) {
	if !ValidName(name) {
		return "", fmt.Errorf("invalid account name %q (letters, digits, '.', '_', '-'; at most %d)", name, MaxNameLen)
	}
	if st.AccountByName(name) != nil {
		return "", fmt.Errorf("account %s exists", name)
	}
	if maxDevices == 0 {
		maxDevices = DefaultMaxDevices
	}
	a := &Account{ID: NewID(), Name: name, RelayAccess: relay, MaxDevices: maxDevices, Invites: true, Manage: true}
	st.Accounts = append(st.Accounts, a)
	return fmt.Sprintf("added account %s (%v)\n", name, a.ID), st.Validate()
}

// RemoveAccount deletes an account, its devices and its invites.
func RemoveAccount(st *State, name string, now time.Time) (string, error) {
	a := st.AccountByName(name)
	if a == nil {
		return "", fmt.Errorf("no account %s", name)
	}
	n := 0
	for _, d := range st.DevicesOf(a.ID) {
		st.tombstone(d, now, ID{}, ID{})
		n++
	}
	st.Devices = slices.DeleteFunc(st.Devices, func(d *Device) bool { return d.Account == a.ID })
	st.Invites = slices.DeleteFunc(st.Invites, func(i *Invite) bool { return i.Account == a.ID })
	st.Accounts = slices.DeleteFunc(st.Accounts, func(x *Account) bool { return x == a })
	return fmt.Sprintf("removed account %s and its %d devices\n", name, n), nil
}

// AddToken adds a device holding a new token bound to no key, as today's
// tokens are, and returns the token. It is the operator's way to add a
// device until invites (§3.4) replace it.
func AddToken(st *State, account, device string, now time.Time) (string, []byte, error) {
	a := st.AccountByName(account)
	if a == nil {
		return "", nil, fmt.Errorf("no account %s", account)
	}
	if device == "" {
		for i := 1; ; i++ {
			if device = fmt.Sprintf("device-%d", i); st.device(a.ID, device) == nil {
				break
			}
		}
	}
	if !ValidName(device) {
		return "", nil, fmt.Errorf("invalid device name %q", device)
	}
	if st.device(a.ID, device) != nil {
		return "", nil, fmt.Errorf("account %s already has a device %s", account, device)
	}
	if len(st.DevicesOf(a.ID)) >= a.MaxDevices {
		return "", nil, fmt.Errorf("account %s is at its device cap (%d)", account, a.MaxDevices)
	}
	tok := NewToken()
	st.Devices = append(st.Devices, &Device{ID: NewID(), Account: a.ID, Name: device,
		TokenHash: TokenHash(tok), Front: FrontVerifier(tok), Created: now.UTC().Truncate(time.Second)})
	return fmt.Sprintf("added device %s/%s\n", account, device), tok, st.Validate()
}

// Revoke revokes one device, ACCOUNT/DEVICE: its record goes, its
// unredeemed invites are cancelled, and a tombstone keeps its ID. With
// descendants, it also revokes every device whose lineage holds it
// (§3.7): those enrolled through its invites, and theirs in turn,
// however long ago and whatever became of the devices between.
func Revoke(st *State, target string, now time.Time, descendants bool) (string, error) {
	account, device, ok := strings.Cut(target, "/")
	if !ok {
		return "", fmt.Errorf("want ACCOUNT/DEVICE, not %q", target)
	}
	a := st.AccountByName(account)
	if a == nil {
		return "", fmt.Errorf("no account %s", account)
	}
	d := st.device(a.ID, device)
	if d == nil {
		return "", fmt.Errorf("account %s has no device %s", account, device)
	}
	gone := []*Device{d}
	if descendants {
		for _, x := range st.Devices {
			if slices.Contains(x.Lineage, d.ID) {
				gone = append(gone, x)
			}
		}
	}
	var b strings.Builder
	for _, x := range gone {
		st.revoke(x, now, ID{}, ID{})
		fmt.Fprintf(&b, "revoked %s/%s\n", account, x.Name)
	}
	return b.String(), nil
}

// revoke removes a device, cancels its unredeemed invites, and leaves a
// tombstone. A revocation by a device (by, for its request) keeps the
// record, for Restore.
func (st *State) revoke(d *Device, now time.Time, by, request ID) {
	st.tombstone(d, now, by, request)
	st.Devices = slices.DeleteFunc(st.Devices, func(x *Device) bool { return x == d })
	st.Invites = slices.DeleteFunc(st.Invites, func(i *Invite) bool { return i.By == d.ID && i.Redeemed.IsZero() })
}

// Rotate revokes every device and invite of an account and keeps the
// account and its policy (§3.7), for when it is unclear which device was
// compromised. The caller adds a fresh operator invite.
func Rotate(st *State, account string, now time.Time) (string, error) {
	a := st.AccountByName(account)
	if a == nil {
		return "", fmt.Errorf("no account %s", account)
	}
	devices := st.DevicesOf(a.ID)
	for _, d := range devices {
		st.revoke(d, now, ID{}, ID{})
	}
	st.Invites = slices.DeleteFunc(st.Invites, func(i *Invite) bool { return i.Account == a.ID })
	// Devices revoked by devices before the rotation stay revoked: their
	// revocations become final, like the operator's (the request stays,
	// to answer its repeats).
	for _, t := range st.Revoked {
		if d, err := parseDevice(t.Rest); err == nil && d.Account == a.ID {
			t.Rest = ""
		}
	}
	return fmt.Sprintf("rotated account %s: revoked its %d devices and cancelled its invites\n", account, len(devices)), nil
}

func (st *State) device(account ID, name string) *Device {
	for _, d := range st.Devices {
		if d.Account == account && d.Name == name {
			return d
		}
	}
	return nil
}

func (st *State) tombstone(d *Device, now time.Time, by, request ID) {
	// A restored device's earlier tombstone gives way to this one.
	st.Revoked = slices.DeleteFunc(st.Revoked, func(x *Tombstone) bool { return x.ID == d.ID })
	t := &Tombstone{ID: d.ID, Until: now.Add(TombstoneLife).UTC().Truncate(time.Second), TokenHash: d.TokenHash, By: by, Request: request}
	if !by.IsZero() {
		t.Rest = d.record()
	}
	st.Revoked = append(st.Revoked, t)
}

// List describes every account and its devices, each device under the
// one that invited it.
func List(st *State) string {
	var b strings.Builder
	tw := tabwriter.NewWriter(&b, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "generation %d", st.Generation)
	if st.Lease.Holder != "" {
		fmt.Fprintf(tw, ", lease held by %s until %s", st.Lease.Holder, stamp(st.Lease.Expires))
	}
	fmt.Fprintln(tw)
	for _, a := range st.Accounts {
		opts := []string{fmt.Sprintf("max_devices=%d", a.MaxDevices), "invites=" + yesNo(a.Invites), "manage=" + yesNo(a.Manage)}
		if a.RelayAccess {
			opts = append([]string{"relay"}, opts...)
		}
		fmt.Fprintf(tw, "%s\t%v\t%s\n", a.Name, a.ID, strings.Join(opts, " "))
		for _, d := range st.DevicesOf(a.ID) {
			key := "unbound"
			if d.Key != nil {
				key = fmt.Sprintf("key %x", d.Key[:8])
			}
			fmt.Fprintf(tw, "  %s%s\t%v\t%s, created %s\n", strings.Repeat("  ", len(d.Lineage)), d.Name, d.ID, key, stamp(d.Created))
		}
		for _, i := range st.Invites {
			if i.Account != a.ID {
				continue
			}
			state := "unredeemed, expires " + stamp(i.Expires)
			if !i.Redeemed.IsZero() {
				state = fmt.Sprintf("redeemed by %v", i.Redeemed)
			}
			if !i.By.IsZero() {
				by := i.By.String()
				if d := st.DeviceByID(i.By); d != nil {
					by = d.Name
				}
				state += ", minted by " + by
			}
			fmt.Fprintf(tw, "  invite %v\t\t%s\n", i.ID, state)
		}
		for _, t := range st.Revoked {
			d, err := parseDevice(t.Rest)
			if t.By.IsZero() || err != nil || d.Account != a.ID {
				continue
			}
			by := t.By.String()
			if x := st.DeviceByID(t.By); x != nil {
				by = x.Name
			}
			fmt.Fprintf(tw, "  revoked %s\t%v\tby %s; restore until %s\n", d.Name, d.ID, by, stamp(t.Until))
		}
	}
	tw.Flush()
	return b.String()
}
