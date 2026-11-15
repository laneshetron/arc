package accounts

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Invite lifetimes and caps (§3.6).
const (
	DefaultInviteTTL = 48 * time.Hour // an operator invite's
	MintedInviteTTL  = 24 * time.Hour // a device-minted invite's
	// MaxOutstanding is how many unredeemed, unexpired invites an
	// account may have before its devices are refused more.
	MaxOutstanding = 2
	// InviteKeySize is the length of the relay secret minted invites
	// are derived from.
	InviteKeySize = 32
)

// Redemption refusals (§3.4). ErrInviteUnknown is also a wrong secret.
var (
	ErrInviteUnknown = errors.New("accounts: unknown invite")
	ErrInviteUsed    = errors.New("accounts: invite already redeemed by another device")
	ErrInviteExpired = errors.New("accounts: invite expired")
	ErrDeviceCap     = errors.New("accounts: account at its device cap")
)

// Minting refusals (§3.6). ErrInviteCap and ErrLineageFull are refused
// as CAPACITY, like ErrDeviceCap; ErrNotPermitted as UNAUTHORIZED.
var (
	ErrNotPermitted = errors.New("accounts: this device may not mint invites")
	ErrInviteCap    = fmt.Errorf("accounts: the account has %d unredeemed invites", MaxOutstanding)
	ErrLineageFull  = fmt.Errorf("accounts: the device's lineage is full (%d entries)", MaxLineage)
	// ErrInviteKeyChanged: the invite a repeated request minted was
	// derived from another invite key, so it cannot be recomputed; the
	// request is answered as expired, and the device asks afresh.
	ErrInviteKeyChanged = errors.New("accounts: the invite was minted with another invite key")
)

// DeriveInvite is a minted invite's ID and secret (§3.6): derived from
// the relay's invite key, so a repeat of the request that minted it is
// answered with the same invite without the secret being stored, and a
// fresh mint at a later generation never repeats an old one.
func DeriveInvite(key []byte, device, request ID, gen uint64) (ID, [16]byte) {
	derive := func(label string) []byte {
		m := hmac.New(sha256.New, key)
		m.Write([]byte(label))
		m.Write(device[:])
		m.Write(request[:])
		m.Write(binary.BigEndian.AppendUint64(nil, gen))
		return m.Sum(nil)
	}
	return ID(derive("ARC/1 invite id")[:8]), [16]byte(derive("ARC/1 invite secret")[:16])
}

// MintedBy returns the invite device minted for request, or nil.
func (s *State) MintedBy(device, request ID) *Invite {
	for _, i := range s.Invites {
		if i.By == device && i.Request == request {
			return i
		}
	}
	return nil
}

// Outstanding counts an account's invites neither redeemed nor expired.
func (s *State) Outstanding(account ID, now time.Time) int {
	n := 0
	for _, i := range s.Invites {
		if i.Account == account && i.Redeemed.IsZero() && now.Before(i.Expires) {
			n++
		}
	}
	return n
}

// MayMint reports whether the device may mint invites at all: it is
// bound to a key, and its account allows it (§3.1, §3.6).
func (s *State) MayMint(d *Device) bool {
	a := s.AccountByID(d.Account)
	return a != nil && a.Invites && d.Bound()
}

// MintInvite answers a device's request for an invite to its account
// (§3.6). A repeat of a request whose invite is kept returns that invite,
// recomputed (minted reports false), or ErrInviteExpired once it has
// expired; otherwise it mints one, at the generation of the transaction
// that commits st, and adds its record. key is the relay's invite key.
func MintInvite(st *State, key []byte, device, request ID, now time.Time) (i *Invite, secret [16]byte, minted bool, err error) {
	if len(key) != InviteKeySize {
		return nil, secret, false, errors.New("accounts: no invite key")
	}
	d := st.DeviceByID(device)
	if d == nil || !st.MayMint(d) {
		return nil, secret, false, ErrNotPermitted
	}
	if i := st.MintedBy(device, request); i != nil {
		if !now.Before(i.Expires) {
			return nil, secret, false, ErrInviteExpired
		}
		id, secret := DeriveInvite(key, device, request, i.Gen)
		if h := sha256.Sum256(secret[:]); id != i.ID || h != i.SecretHash {
			return nil, [16]byte{}, false, ErrInviteKeyChanged
		}
		return i, secret, false, nil
	}
	a := st.AccountByID(d.Account)
	switch {
	case len(d.Lineage) >= MaxLineage:
		return nil, secret, false, ErrLineageFull
	case len(st.DevicesOf(a.ID)) >= a.MaxDevices:
		return nil, secret, false, ErrDeviceCap
	case st.Outstanding(a.ID, now) >= MaxOutstanding:
		return nil, secret, false, ErrInviteCap
	}
	gen := st.Generation + 1 // the transaction committing st (Writer.Commit)
	id, secret := DeriveInvite(key, device, request, gen)
	i = &Invite{ID: id, Account: a.ID, SecretHash: sha256.Sum256(secret[:]), Front: FrontVerifier(secret[:]),
		Expires: now.Add(MintedInviteTTL).UTC().Truncate(time.Second), By: device, Request: request, Gen: gen}
	st.Invites = append(st.Invites, i)
	return i, secret, true, st.Validate()
}

// InviteByID returns the invite, or nil.
func (s *State) InviteByID(id ID) *Invite {
	for _, i := range s.Invites {
		if i.ID == id {
			return i
		}
	}
	return nil
}

// DeviceByID returns the device, or nil.
func (s *State) DeviceByID(id ID) *Device {
	for _, d := range s.Devices {
		if d.ID == id {
			return d
		}
	}
	return nil
}

// AddInvite adds an operator invite to account, lasting ttl, and returns
// it with its secret, which is never stored: only its hash is (§3.1).
func AddInvite(st *State, account string, ttl time.Duration, now time.Time) (*Invite, [16]byte, error) {
	var secret [16]byte
	a := st.AccountByName(account)
	if a == nil {
		return nil, secret, fmt.Errorf("no account %s", account)
	}
	if ttl <= 0 {
		ttl = DefaultInviteTTL
	}
	rand.Read(secret[:])
	i := &Invite{ID: NewID(), Account: a.ID, SecretHash: sha256.Sum256(secret[:]), Front: FrontVerifier(secret[:]),
		Expires: now.Add(ttl).UTC().Truncate(time.Second)}
	st.Invites = append(st.Invites, i)
	return i, secret, st.Validate()
}

// CheckInvite finds the invite id whose secret is secret, comparing the
// hash in constant time.
func (s *State) CheckInvite(id ID, secret []byte) (*Invite, error) {
	i := s.InviteByID(id)
	h := sha256.Sum256(secret)
	if i == nil || subtle.ConstantTimeCompare(h[:], i.SecretHash[:]) != 1 {
		return nil, ErrInviteUnknown
	}
	return i, nil
}

// RedeemedBy reports whether invite i enrolled the device with this
// token and Noise static key: a repeat of the redemption that made it.
func (s *State) RedeemedBy(i *Invite, token, key []byte) *Device {
	if i.Redeemed == (ID{}) {
		return nil
	}
	d := s.DeviceByID(i.Redeemed)
	if d == nil || d.TokenHash != TokenHash(token) || !bytes.Equal(d.Key, key) {
		return nil
	}
	return d
}

// Redeem enrolls a device with an invite (§3.4): the device registers
// token, bound to the Noise static key, under a name derived from name
// (made unique in the account). A repeat of the redemption that made a
// device returns that device, even past the invite's expiry.
func Redeem(st *State, id ID, secret, token, key []byte, name string, now time.Time) (*Device, error) {
	i, err := st.CheckInvite(id, secret)
	if err != nil {
		return nil, err
	}
	if d := st.RedeemedBy(i, token, key); d != nil {
		return d, nil
	}
	switch {
	case !i.Redeemed.IsZero():
		return nil, ErrInviteUsed
	case !now.Before(i.Expires):
		return nil, ErrInviteExpired
	case !ValidToken(token) || len(key) != 32:
		return nil, errors.New("accounts: malformed enrollment")
	}
	a := st.AccountByID(i.Account)
	if a == nil {
		return nil, ErrInviteUnknown
	}
	if len(st.DevicesOf(a.ID)) >= a.MaxDevices {
		return nil, ErrDeviceCap
	}
	h := TokenHash(token)
	for _, d := range st.Devices {
		if d.TokenHash == h {
			return nil, errors.New("accounts: token already registered")
		}
	}
	d := &Device{ID: NewID(), Account: a.ID, Name: uniqueName(st, a.ID, name), TokenHash: h, Front: FrontVerifier(token),
		Key: bytes.Clone(key), Via: i.ID, Created: now.UTC().Truncate(time.Second)}
	if !i.By.IsZero() {
		// The minter's lineage, then the minter (§3.1). Its revocation
		// cancelled its unredeemed invites, so it is here.
		m := st.DeviceByID(i.By)
		if m == nil {
			return nil, ErrInviteUnknown
		}
		d.Lineage = append(slices.Clone(m.Lineage), m.ID)
		if len(d.Lineage) > MaxLineage {
			return nil, ErrLineageFull
		}
	}
	st.Devices = append(st.Devices, d)
	i.Redeemed = d.ID
	return d, st.Validate()
}

// uniqueName makes a device name for the account from the client's
// proposal: valid, and unique, with -2, -3, … appended on a clash.
func uniqueName(st *State, account ID, name string) string {
	if !ValidName(name) {
		name = "device"
	}
	for n := 1; ; n++ {
		try := name
		if n > 1 {
			suffix := fmt.Sprintf("-%d", n)
			try = name[:min(len(name), MaxNameLen-len(suffix))] + suffix
		}
		if st.device(account, try) == nil {
			return try
		}
	}
}
