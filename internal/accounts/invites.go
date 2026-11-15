package accounts

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"
)

// DefaultInviteTTL is how long an operator invite lasts (§3.6).
const DefaultInviteTTL = 48 * time.Hour

// Redemption refusals (§3.4). ErrInviteUnknown is also a wrong secret.
var (
	ErrInviteUnknown = errors.New("accounts: unknown invite")
	ErrInviteUsed    = errors.New("accounts: invite already redeemed by another device")
	ErrInviteExpired = errors.New("accounts: invite expired")
	ErrDeviceCap     = errors.New("accounts: account at its device cap")
)

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
		return nil, errors.New("accounts: device-minted invites are not supported yet")
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
