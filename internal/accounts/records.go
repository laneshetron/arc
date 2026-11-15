// Package accounts keeps a relay's accounts and devices (spec
// self-service-accounts.md §3.1–3.2): the records, their file format, the
// durable store that is their commit point, and the writer lease that
// lets one relay at a time authenticate from them and change them.
package accounts

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Limits (§3.1, §3.2).
const (
	MaxAccounts       = 256
	MaxDevicesLimit   = 16 // the highest max_devices an account may have
	DefaultMaxDevices = 5
	MaxLineage        = 7 // entries; a chain is at most 8 devices
	MaxNameLen        = 32
	TombstoneLife     = 7 * 24 * time.Hour
)

const header = "# arc-accounts 2"

// An ID is a record's immutable random identifier.
type ID [8]byte

func (id ID) String() string { return hex.EncodeToString(id[:]) }
func (id ID) IsZero() bool   { return id == ID{} }

// NewID returns a random ID.
func NewID() ID {
	var id ID
	if _, err := rand.Read(id[:]); err != nil {
		panic(err)
	}
	return id
}

func parseID(s string) (ID, error) {
	var id ID
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != len(id) {
		return id, fmt.Errorf("bad ID %q", s)
	}
	copy(id[:], b)
	if id.IsZero() {
		return id, errors.New("zero ID")
	}
	return id, nil
}

// An Account isolates its devices' clients from every other account's,
// and holds the policy they share.
type Account struct {
	ID          ID
	Name        string
	RelayAccess bool
	MaxDevices  int
	Invites     bool // devices may mint invites (§3.6)
	Manage      bool // devices may list and revoke devices (§3.8)
}

// A Device is one credential of an account.
type Device struct {
	ID        ID
	Account   ID
	Name      string
	TokenHash [32]byte // SHA-256 of the token's text
	Front     [16]byte // front admission verifier (§3.5)
	Key       []byte   // Noise static public key it is bound to; nil for a legacy device
	Lineage   []ID     // oldest first, ending with its minter
	Via       ID       // the invite it enrolled with, for audit
	Created   time.Time
}

// record is the device's line in the file.
func (d *Device) record() string {
	var b strings.Builder
	fmt.Fprintf(&b, "device %v %v %s token=%x front=%x", d.ID, d.Account, d.Name, d.TokenHash, d.Front)
	if d.Key != nil {
		fmt.Fprintf(&b, " key=%x", d.Key)
	}
	fmt.Fprintf(&b, " lineage=%s", joinIDs(d.Lineage))
	if !d.Via.IsZero() {
		fmt.Fprintf(&b, " via=%v", d.Via)
	}
	fmt.Fprintf(&b, " created=%s", stamp(d.Created))
	return b.String()
}

// parseDevice reads a device's line, as record writes it.
func parseDevice(line string) (*Device, error) {
	var s State
	if !strings.HasPrefix(line, "device ") {
		return nil, errors.New("not a device record")
	}
	if err := s.parseRecord(line); err != nil {
		return nil, err
	}
	return s.Devices[0], nil
}

// Bound reports whether the device's token authenticates only its own key.
func (d *Device) Bound() bool { return d.Key != nil }

// An Invite is a single-use enrollment secret (§3.3–3.6). Its records are
// parsed and kept here; they are created and redeemed elsewhere.
type Invite struct {
	ID         ID
	Account    ID
	SecretHash [32]byte
	Front      [16]byte
	Expires    time.Time
	By         ID // the device that minted it; zero for an operator invite
	Request    ID // the minting request, with By
	Gen        uint64
	Redeemed   ID // the device it enrolled
}

// A Tombstone remembers a revoked device until Until.
type Tombstone struct {
	ID    ID
	Until time.Time
	By    ID     // the device that revoked it, for a device's revocation
	Rest  string // the revoked record, for restore
}

// A Lease names the one writer that may commit and authenticate (§3.2).
type Lease struct {
	Holder  string // instance ID or command; no spaces or commas
	Token   string // random, per acquisition
	Expires time.Time
}

// Held reports whether the lease names a holder whose lease runs past t.
func (l Lease) Held(t time.Time) bool { return l.Holder != "" && t.Before(l.Expires) }

// State is every record, at one committed generation.
type State struct {
	Generation uint64
	Lease      Lease
	Accounts   []*Account
	Devices    []*Device
	Invites    []*Invite
	Revoked    []*Tombstone
}

// Clone returns a deep copy, for a transaction to change.
func (s *State) Clone() *State {
	c := &State{Generation: s.Generation, Lease: s.Lease}
	for _, a := range s.Accounts {
		x := *a
		c.Accounts = append(c.Accounts, &x)
	}
	for _, d := range s.Devices {
		x := *d
		x.Key = slices.Clone(d.Key)
		x.Lineage = slices.Clone(d.Lineage)
		c.Devices = append(c.Devices, &x)
	}
	for _, i := range s.Invites {
		x := *i
		c.Invites = append(c.Invites, &x)
	}
	for _, t := range s.Revoked {
		x := *t
		c.Revoked = append(c.Revoked, &x)
	}
	return c
}

// AccountByName returns the named account, or nil.
func (s *State) AccountByName(name string) *Account {
	for _, a := range s.Accounts {
		if a.Name == name {
			return a
		}
	}
	return nil
}

// AccountByID returns the account, or nil.
func (s *State) AccountByID(id ID) *Account {
	for _, a := range s.Accounts {
		if a.ID == id {
			return a
		}
	}
	return nil
}

// DevicesOf returns an account's devices.
func (s *State) DevicesOf(account ID) []*Device {
	var out []*Device
	for _, d := range s.Devices {
		if d.Account == account {
			out = append(out, d)
		}
	}
	return out
}

// TokenHash is how a token is stored: SHA-256 of its text (§3.4).
func TokenHash(token []byte) [32]byte { return sha256.Sum256(token) }

// FrontVerifier is the front admission value derived from a token or an
// invite secret (§3.5).
func FrontVerifier(secret []byte) [16]byte {
	h := sha256.Sum256(append([]byte("ARC/1 front admission"), secret...))
	return [16]byte(h[:16])
}

// NewToken returns a fresh device token: 32 random bytes, base64url
// without padding (§3.4).
func NewToken() []byte {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return []byte(base64url(b[:]))
}

// ValidName reports whether s may name an account or a device.
func ValidName(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > MaxNameLen {
		return false
	}
	for _, c := range []byte(s) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// ValidToken reports whether t may be a token: printable ASCII, so that
// it never begins with the enrollment credential's zero byte (§3.4).
func ValidToken(t []byte) bool {
	if len(t) == 0 || len(t) > 256 {
		return false
	}
	for _, c := range t {
		if c <= ' ' || c > '~' {
			return false
		}
	}
	return true
}

// Validate checks the invariants every committed state holds.
func (s *State) Validate() error {
	if len(s.Accounts) > MaxAccounts {
		return fmt.Errorf("%d accounts, at most %d", len(s.Accounts), MaxAccounts)
	}
	ids := map[ID]bool{}
	names := map[string]bool{}
	for _, a := range s.Accounts {
		if ids[a.ID] {
			return fmt.Errorf("ID %v repeated", a.ID)
		}
		ids[a.ID] = true
		if !ValidName(a.Name) {
			return fmt.Errorf("invalid account name %q", a.Name)
		}
		if names[a.Name] {
			return fmt.Errorf("account name %q repeated", a.Name)
		}
		names[a.Name] = true
		if a.MaxDevices < 1 || a.MaxDevices > MaxDevicesLimit {
			return fmt.Errorf("account %s: max_devices %d, want 1 to %d", a.Name, a.MaxDevices, MaxDevicesLimit)
		}
	}
	tokens := map[[32]byte]bool{}
	devNames := map[string]bool{}
	count := map[ID]int{}
	for _, d := range s.Devices {
		if ids[d.ID] {
			return fmt.Errorf("ID %v repeated", d.ID)
		}
		ids[d.ID] = true
		a := s.AccountByID(d.Account)
		if a == nil {
			return fmt.Errorf("device %v: no account %v", d.ID, d.Account)
		}
		if !ValidName(d.Name) {
			return fmt.Errorf("device %v: invalid name %q", d.ID, d.Name)
		}
		if k := a.ID.String() + "/" + d.Name; devNames[k] {
			return fmt.Errorf("account %s: device name %q repeated", a.Name, d.Name)
		} else {
			devNames[k] = true
		}
		if tokens[d.TokenHash] {
			return fmt.Errorf("account %s: a token is repeated", a.Name)
		}
		tokens[d.TokenHash] = true
		if d.Key != nil && len(d.Key) != 32 {
			return fmt.Errorf("device %v: key of %d bytes", d.ID, len(d.Key))
		}
		if len(d.Lineage) > MaxLineage {
			return fmt.Errorf("device %v: lineage of %d, at most %d", d.ID, len(d.Lineage), MaxLineage)
		}
		count[a.ID]++
	}
	for _, a := range s.Accounts {
		if count[a.ID] > a.MaxDevices {
			return fmt.Errorf("account %s: %d devices, at most %d", a.Name, count[a.ID], a.MaxDevices)
		}
	}
	for _, i := range s.Invites {
		if ids[i.ID] {
			return fmt.Errorf("ID %v repeated", i.ID)
		}
		ids[i.ID] = true
		if s.AccountByID(i.Account) == nil {
			return fmt.Errorf("invite %v: no account %v", i.ID, i.Account)
		}
		// Marshal writes by= and req= together, and Parse refuses a zero ID.
		if i.By.IsZero() != i.Request.IsZero() {
			return fmt.Errorf("invite %v: minting device and request not both set", i.ID)
		}
	}
	return nil
}

// Prune drops tombstones and invites past their retention at now.
func (s *State) Prune(now time.Time) {
	s.Revoked = slices.DeleteFunc(s.Revoked, func(t *Tombstone) bool { return !now.Before(t.Until) })
	s.Invites = slices.DeleteFunc(s.Invites, func(i *Invite) bool { return !now.Before(i.Expires.Add(TombstoneLife)) })
}

// Marshal encodes s in the version-2 format.
func (s *State) Marshal() []byte {
	var b bytes.Buffer
	lease := "-"
	if s.Lease.Holder != "" {
		lease = s.Lease.Holder + "," + s.Lease.Token + "," + stamp(s.Lease.Expires)
	}
	fmt.Fprintf(&b, "%s generation=%d lease=%s\n", header, s.Generation, lease)
	for _, a := range s.Accounts {
		fmt.Fprintf(&b, "account %v %s", a.ID, a.Name)
		if a.RelayAccess {
			b.WriteString(" relay")
		}
		fmt.Fprintf(&b, " max_devices=%d invites=%s manage=%s\n", a.MaxDevices, yesNo(a.Invites), yesNo(a.Manage))
	}
	for _, d := range s.Devices {
		b.WriteString(d.record())
		b.WriteByte('\n')
	}
	for _, i := range s.Invites {
		fmt.Fprintf(&b, "invite %v %v %x front=%x expires=%s", i.ID, i.Account, i.SecretHash, i.Front, stamp(i.Expires))
		if !i.By.IsZero() {
			fmt.Fprintf(&b, " by=%v req=%v gen=%d", i.By, i.Request, i.Gen)
		}
		if !i.Redeemed.IsZero() {
			fmt.Fprintf(&b, " redeemed=%v", i.Redeemed)
		}
		b.WriteByte('\n')
	}
	for _, t := range s.Revoked {
		fmt.Fprintf(&b, "revoked %v until=%s", t.ID, stamp(t.Until))
		if !t.By.IsZero() {
			fmt.Fprintf(&b, " by=%v", t.By)
		}
		if t.Rest != "" {
			fmt.Fprintf(&b, " record=%s", t.Rest)
		}
		b.WriteByte('\n')
	}
	return b.Bytes()
}

// Parse decodes an accounts file: the version-2 format, or today's
// tokens file (NAME TOKEN [relay], or a bare TOKEN), which it migrates
// (§3.1) as of now, at generation 0 with no lease.
func Parse(data []byte, now time.Time) (*State, error) {
	first, _, _ := bytes.Cut(data, []byte("\n"))
	if !bytes.HasPrefix(first, []byte(header)) {
		return migrate(data, now)
	}
	s := &State{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(nil, 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if n == 1 {
			if err := s.parseHeader(line); err != nil {
				return nil, fmt.Errorf("accounts line 1: %w", err)
			}
			continue
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if err := s.parseRecord(line); err != nil {
			return nil, fmt.Errorf("accounts line %d: %w", n, err)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("accounts: %w", err)
	}
	return s, nil
}

func (s *State) parseHeader(line string) error {
	for _, f := range strings.Fields(strings.TrimPrefix(line, header)) {
		k, v, _ := strings.Cut(f, "=")
		switch k {
		case "generation":
			g, err := strconv.ParseUint(v, 10, 64)
			if err != nil {
				return fmt.Errorf("bad generation %q", v)
			}
			s.Generation = g
		case "lease":
			if v == "-" {
				continue
			}
			parts := strings.Split(v, ",")
			if len(parts) != 3 || parts[0] == "" {
				return fmt.Errorf("bad lease %q", v)
			}
			t, err := parseStamp(parts[2])
			if err != nil {
				return err
			}
			s.Lease = Lease{Holder: parts[0], Token: parts[1], Expires: t}
		default:
			return fmt.Errorf("unknown header field %q", k)
		}
	}
	return nil
}

func (s *State) parseRecord(line string) error {
	f := strings.Fields(line)
	kind, pos, opts := f[0], []string{}, map[string]string{}
	flags := map[string]bool{}
	for _, x := range f[1:] {
		if k, v, ok := strings.Cut(x, "="); ok {
			if k == "record" {
				// The rest of the line is the revoked record.
				_, rest, _ := strings.Cut(line, " record=")
				opts[k] = rest
				break
			}
			opts[k] = v
		} else if len(opts) == 0 && len(flags) == 0 {
			pos = append(pos, x)
		} else {
			flags[x] = true
		}
	}
	var err error
	id := func(s string) ID {
		if err != nil {
			return ID{}
		}
		var v ID
		v, err = parseID(s)
		return v
	}
	optID := func(k string) ID {
		if v, ok := opts[k]; ok {
			return id(v)
		}
		return ID{}
	}
	switch kind {
	case "account":
		// account ID NAME [relay] key=value...
		if len(pos) == 3 && pos[2] == "relay" {
			pos, flags["relay"] = pos[:2], true
		}
		if len(pos) != 2 {
			return errors.New("want account ID NAME [relay] [max_devices=N] [invites=yes|no] [manage=yes|no]")
		}
		a := &Account{ID: id(pos[0]), Name: pos[1], RelayAccess: flags["relay"], MaxDevices: DefaultMaxDevices, Invites: true, Manage: true}
		delete(flags, "relay")
		if v, ok := opts["max_devices"]; ok {
			if a.MaxDevices, err = strconv.Atoi(v); err != nil {
				return fmt.Errorf("bad max_devices %q", v)
			}
		}
		if v, ok := opts["invites"]; ok {
			a.Invites, err = parseYesNo(v)
		}
		if v, ok := opts["manage"]; ok && err == nil {
			a.Manage, err = parseYesNo(v)
		}
		s.Accounts = append(s.Accounts, a)
	case "device":
		if len(pos) != 3 {
			return errors.New("want device ID ACCOUNT_ID NAME token=... front=... lineage=... created=...")
		}
		d := &Device{ID: id(pos[0]), Account: id(pos[1]), Name: pos[2], Via: optID("via")}
		if err == nil {
			err = hexInto(d.TokenHash[:], opts["token"], "token")
		}
		if err == nil {
			err = hexInto(d.Front[:], opts["front"], "front")
		}
		if v, ok := opts["key"]; ok && err == nil {
			if d.Key, err = hex.DecodeString(v); err != nil {
				err = fmt.Errorf("bad key %q", v)
			}
		}
		if v := opts["lineage"]; v != "" && err == nil {
			for _, x := range strings.Split(v, ",") {
				d.Lineage = append(d.Lineage, id(x))
			}
		}
		if err == nil {
			d.Created, err = parseStamp(opts["created"])
		}
		s.Devices = append(s.Devices, d)
	case "invite":
		if len(pos) != 3 {
			return errors.New("want invite ID ACCOUNT_ID HASH front=... expires=...")
		}
		i := &Invite{ID: id(pos[0]), Account: id(pos[1]), By: optID("by"), Request: optID("req"), Redeemed: optID("redeemed")}
		if err == nil {
			err = hexInto(i.SecretHash[:], pos[2], "hash")
		}
		if err == nil {
			err = hexInto(i.Front[:], opts["front"], "front")
		}
		if err == nil {
			i.Expires, err = parseStamp(opts["expires"])
		}
		if v, ok := opts["gen"]; ok && err == nil {
			if i.Gen, err = strconv.ParseUint(v, 10, 64); err != nil {
				err = fmt.Errorf("bad gen %q", v)
			}
		}
		s.Invites = append(s.Invites, i)
	case "revoked":
		if len(pos) != 1 {
			return errors.New("want revoked ID until=T")
		}
		t := &Tombstone{ID: id(pos[0]), By: optID("by"), Rest: opts["record"]}
		if err == nil {
			t.Until, err = parseStamp(opts["until"])
		}
		s.Revoked = append(s.Revoked, t)
	default:
		return fmt.Errorf("unknown record %q", kind)
	}
	if err == nil && len(flags) > 0 {
		for k := range flags {
			return fmt.Errorf("unknown option %q", k)
		}
	}
	return err
}

// migrate converts today's tokens file: one account per name, one
// device per token, named legacy-1, legacy-2, ... and bound to no key.
func migrate(data []byte, now time.Time) (*State, error) {
	s := &State{}
	byName := map[string]*Account{}
	seen := map[string]bool{}
	n, legacy := 0, map[ID]int{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		n++
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		var name, token string
		relay := false
		switch len(f) {
		case 1:
			name, token = fmt.Sprintf("line%d", n), f[0]
		case 2, 3:
			name, token = f[0], f[1]
			if len(f) == 3 {
				if f[2] != "relay" {
					return nil, fmt.Errorf("tokens line %d: unknown option %q (want relay)", n, f[2])
				}
				relay = true
			}
		default:
			return nil, fmt.Errorf("tokens line %d: want NAME TOKEN [relay] or TOKEN", n)
		}
		if !ValidName(name) {
			return nil, fmt.Errorf("tokens line %d: invalid account name %q", n, name)
		}
		if !ValidToken([]byte(token)) {
			return nil, fmt.Errorf("tokens line %d: a token must be printable ASCII", n)
		}
		if seen[token] {
			return nil, fmt.Errorf("tokens line %d: token repeated", n)
		}
		seen[token] = true
		a := byName[name]
		switch {
		case a == nil:
			a = &Account{ID: NewID(), Name: name, RelayAccess: relay, MaxDevices: DefaultMaxDevices, Invites: true, Manage: true}
			byName[name] = a
			s.Accounts = append(s.Accounts, a)
		case len(f) == 1:
			return nil, fmt.Errorf("tokens line %d: account name %s is taken", n, name)
		case a.RelayAccess != relay:
			return nil, fmt.Errorf("tokens line %d: account %s is listed with and without relay", n, name)
		}
		legacy[a.ID]++
		if legacy[a.ID] > a.MaxDevices {
			a.MaxDevices = min(legacy[a.ID], MaxDevicesLimit)
		}
		s.Devices = append(s.Devices, &Device{
			ID: NewID(), Account: a.ID, Name: fmt.Sprintf("legacy-%d", legacy[a.ID]),
			TokenHash: TokenHash([]byte(token)), Front: FrontVerifier([]byte(token)), Created: now.UTC().Truncate(time.Second),
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("tokens: %w", err)
	}
	return s, nil
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func parseStamp(v string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, v)
	if err != nil {
		return t, fmt.Errorf("bad time %q", v)
	}
	return t, nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func parseYesNo(v string) (bool, error) {
	switch v {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	}
	return false, fmt.Errorf("want yes or no, not %q", v)
}

func hexInto(dst []byte, v, what string) error {
	b, err := hex.DecodeString(v)
	if err != nil || len(b) != len(dst) {
		return fmt.Errorf("bad %s %q", what, v)
	}
	copy(dst, b)
	return nil
}

func joinIDs(ids []ID) string {
	s := make([]string, len(ids))
	for i, id := range ids {
		s[i] = id.String()
	}
	return strings.Join(s, ",")
}
