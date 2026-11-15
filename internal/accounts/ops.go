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
		st.tombstone(d, now, ID{})
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
// unredeemed invites are cancelled, and a tombstone keeps its ID.
func Revoke(st *State, target string, now time.Time) (string, error) {
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
	st.tombstone(d, now, ID{})
	st.Devices = slices.DeleteFunc(st.Devices, func(x *Device) bool { return x == d })
	st.Invites = slices.DeleteFunc(st.Invites, func(i *Invite) bool { return i.By == d.ID && i.Redeemed.IsZero() })
	return fmt.Sprintf("revoked %s\n", target), nil
}

func (st *State) device(account ID, name string) *Device {
	for _, d := range st.Devices {
		if d.Account == account && d.Name == name {
			return d
		}
	}
	return nil
}

func (st *State) tombstone(d *Device, now time.Time, by ID) {
	st.Revoked = append(st.Revoked, &Tombstone{ID: d.ID, Until: now.Add(TombstoneLife).UTC().Truncate(time.Second), By: by})
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
			fmt.Fprintf(tw, "  invite %v\t\t%s\n", i.ID, state)
		}
	}
	tw.Flush()
	return b.String()
}
