// Package beacon reads the DNS lifeline's signed records
// (spec/dns-lifeline.md §3): it builds the two fixed query profiles of §3.2
// and parses the TXT answer, so the rules of §3.3 can be applied on top of
// the codec in beacon.go.
package beacon

import (
	"crypto/rand"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// b32 is the no-padding lowercase base32 the beacon grammar uses. `0` and
// `1` are outside its alphabet, which is what lets a decoder tell padding
// labels from a sequence label from data (§2.2.1).
var b32 = base32.StdEncoding.WithPadding(base32.NoPadding)

const (
	// maxName is the wire length a DNS name may occupy (RFC 1035 §2.3.4).
	maxName = 255
	// maxLabel is DNS's per-label limit, from the same section.
	maxLabel = 63
)

// Profile is one of the two query shapes of §3.2. The client sends
// Bootstrap first and retries with EDNS only when the answer is truncated,
// because Bootstrap is what fits any resolver's buffer.
type Profile uint8

const (
	// ProfileBootstrap is a query with no EDNS(0), sized so that a 512-byte
	// answer carries the most the 3× rule allows.
	ProfileBootstrap Profile = iota
	// ProfileEDNS is the same question with a bare OPT record advertising a
	// 1232-byte buffer.
	ProfileEDNS
)

func (p Profile) String() string {
	switch p {
	case ProfileBootstrap:
		return "bootstrap"
	case ProfileEDNS:
		return "edns"
	}
	return fmt.Sprintf("Profile(%d)", uint8(p))
}

// ednsUDPSize is the buffer the EDNS(0) profile advertises. It is the
// profile's *ceiling*, not its answer cap: §3.2's 3× rule is tighter than
// this at every legal name length.
const ednsUDPSize = 1232

// Query overheads: a query is 12 bytes of header, its name, and 4 bytes of
// type and class.
const (
	headerLen  = 12
	questionLt = 4
)

// bootstrapCap is the answer a resolver with no EDNS(0) will send at most.
const bootstrapCap = 512

// Query is one question to send, and the answer budget it admits.
type Query struct {
	// Name is the question name, lowercase, without a trailing dot.
	Name string
	// Wire is the encoded DNS message.
	Wire []byte
	// Profile is the shape that produced it.
	Profile Profile
	// AnswerCap is the largest answer this query may receive: the smaller
	// of the resolver's buffer and 3× the query's own wire size (§3.2). The
	// authority refuses anything above 3×, so a query that underran its
	// padding would be asking for a REFUSED.
	AnswerCap int
	// Suffix is what Decode verifies the signature against.
	Suffix string
}

// NewQuery builds the question for a beacon zone in the given profile, with
// a fresh nonce (§3.1: every query is a distinct name, so no answer can be
// served from a cache or correlated with another). A nil randRead uses
// crypto/rand.
//
// The name is `<nonce>.[0pad...]._arcb.<zone>` (§2.2.1's grammar, reused
// here), and its length is chosen rather than maximized. An answer echoes
// the question in name-compressed form, so a longer name costs answer space
// while the 3× rule pays back only three bytes of cap for every two bytes
// of padding. For the bootstrap profile the two meet at a 171-byte query,
// and §3.2's table is wrong to pad to the 255-byte limit: at 255 a
// bootstrap answer carries a 168-byte signed record, at 155 a 243-byte one.
// For EDNS the 3× rule never catches the 1232-byte buffer, so a full name
// stays best and the record can be 417 bytes.
func NewQuery(zone string, p Profile, randRead func([]byte) (int, error)) (Query, error) {
	if randRead == nil {
		randRead = rand.Read
	}
	if p != ProfileBootstrap && p != ProfileEDNS {
		return Query{}, fmt.Errorf("beacon: unknown profile %v", p)
	}
	suffix := Suffix(zone)
	nonce, err := nonce13(randRead)
	if err != nil {
		return Query{}, err
	}
	name, err := padName(nonce, suffix, p.nameLen())
	if err != nil {
		return Query{}, err
	}
	wire, err := buildQuery(name, p, randRead)
	if err != nil {
		return Query{}, err
	}
	return Query{
		Name:      name,
		Wire:      wire,
		Profile:   p,
		AnswerCap: min(p.cap(), 3*len(wire)),
		Suffix:    suffix,
	}, nil
}

// nameLen is the question name's wire length for the profile: the point
// where the 3× rule and the resolver's buffer admit the largest answer.
//
// For bootstrap they cross at a 171-byte query — the smallest query whose 3×
// covers a full 512-byte answer — so 155 bytes of name. Every name byte past
// that is taken straight out of the record. For EDNS the buffer is 1232 and
// the 3× rule binds at every legal length, so the limit of 255 is the answer.
func (p Profile) nameLen() int {
	if p == ProfileEDNS {
		return maxName
	}
	// The smallest name whose 3× covers a full bootstrap answer. Derived
	// rather than written as 155 so it cannot drift from the constants.
	n := (bootstrapCap+2)/3 - headerLen - questionLt
	if n > maxName {
		n = maxName
	}
	return n
}

// cap is the profile's answer ceiling before the 3× rule.
func (p Profile) cap() int {
	if p == ProfileEDNS {
		return ednsUDPSize
	}
	return bootstrapCap
}

// nonce13 returns 13 lowercase no-padding base32 characters over 8 random
// bytes (§3.1).
func nonce13(randRead func([]byte) (int, error)) (string, error) {
	var b [8]byte
	if _, err := randRead(b[:]); err != nil {
		return "", fmt.Errorf("beacon: nonce: %w", err)
	}
	return strings.ToLower(b32.EncodeToString(b[:])), nil
}

// padName builds `<nonce>.[0pad...]._arcb.<zone>` and pads it as close to
// want wire bytes as whole labels allow, never exceeding it. A zone so long
// that the bare name already exceeds want is used unpadded.
func padName(nonce, suffix string, want int) (string, error) {
	base := nonce + "." + suffix
	room := want - wireLen(base)
	if room < 0 {
		// Nothing to pad; the name is as short as it can be. A zone this
		// long loses answer space but still parses.
		return base, nil
	}
	var labels []string
	for _, n := range padSplit(room) {
		labels = append(labels, "0"+strings.Repeat("0", n-1))
	}
	name := base
	if len(labels) > 0 {
		// Padding sits between the nonce and the suffix, where the grammar
		// of §2.2.1 puts it.
		name = nonce + "." + strings.Join(labels, ".") + "." + suffix
	}
	if w := wireLen(name); w > want {
		return "", fmt.Errorf("beacon: padded name is %d B, over the %d limit", w, want)
	}
	return name, nil
}

// padSplit divides room wire bytes of padding into label lengths, each
// between 2 and 63, whose total cost — a length byte plus contents each —
// is exactly room. It returns nothing when room cannot be spent, which is
// only room of 1 or 2: a single-byte padding label is the bare marker
// §2.2.1 says to reject, and nothing else reaches that low.
func padSplit(room int) []int {
	if room <= 2 {
		return nil
	}
	n := (room + maxLabel - 1) / maxLabel
	if room < 3*n {
		// Each label spends at least one length byte and two contents, so a
		// division into n labels cannot be filled this small; one covers it.
		n = 1
	}
	out := make([]int, n)
	left := room - n // every label owes a length byte
	for i := range out {
		take := min(maxLabel, left-(len(out)-i-1)*2)
		out[i] = take
		left -= take
	}
	return out
}

// wireLen is a name's length on the wire: a length byte per label, the
// labels' bytes, and the root's terminating zero.
func wireLen(name string) int {
	n := 1
	for _, l := range strings.Split(name, ".") {
		n += 1 + len(l)
	}
	return n
}

// buildQuery encodes the DNS message for name.
func buildQuery(name string, p Profile, randRead func([]byte) (int, error)) ([]byte, error) {
	n, err := dnsmessage.NewName(name + ".")
	if err != nil {
		return nil, fmt.Errorf("beacon: %w", err)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{
		ID: randID(randRead),
		// Recursion is the whole point: the client asks a resolver that can
		// reach the operator's nameserver when it cannot.
		RecursionDesired: true,
	})
	if err := b.StartQuestions(); err != nil {
		return nil, err
	}
	if err := b.Question(dnsmessage.Question{
		Name:  n,
		Type:  dnsmessage.TypeTXT,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		return nil, err
	}
	if p == ProfileEDNS {
		if err := b.StartAdditionals(); err != nil {
			return nil, err
		}
		// An OPT record carries the requester's payload size in its class
		// field (RFC 6891 §6.1.2), which is the only place dnsmessage
		// exposes it.
		if err := b.OPTResource(dnsmessage.ResourceHeader{
			Name:  dnsmessage.MustNewName("."),
			Class: dnsmessage.Class(ednsUDPSize),
		}, dnsmessage.OPTResource{}); err != nil {
			return nil, err
		}
	}
	return b.Finish()
}

// randID returns a random DNS transaction ID. The nonce in the name is what
// makes a poll distinct (§3.1); the ID is required for a UDP exchange.
func randID(randRead func([]byte) (int, error)) uint16 {
	var b [2]byte
	if _, err := randRead(b[:]); err != nil {
		return 0
	}
	return uint16(b[0])<<8 | uint16(b[1])
}

// Response is a parsed answer.
type Response struct {
	// Truncated is the TC bit: the authority had more than the answer
	// carried, so the client retries with the larger profile (§3.2).
	Truncated bool
	// Records is every TXT record owned by the queried name, in answer
	// order. A well-formed beacon has one; more are tried in order (§3.3).
	Records []string
}

var (
	errNotResponse = errors.New("beacon: not a response")
	errNoQuestion  = errors.New("beacon: response does not echo the question")
	errForOther    = errors.New("beacon: answer is for another question")
)

// ParseAnswer parses the response to q and returns its TXT contents. It
// verifies nothing about the records: §3.3's rules are the caller's,
// because an unsigned or tampered record is a different outcome from a
// malformed response and the two are logged differently.
//
// A response echoing a different question is refused, which is §3.1's nonce
// rule doing the work a transaction ID cannot: resolvers and the paths to
// them may rewrite the ID, but they cannot invent a nonce.
func ParseAnswer(q Query, msg []byte) (Response, error) {
	var p dnsmessage.Parser
	h, err := p.Start(msg)
	if err != nil {
		return Response{}, fmt.Errorf("beacon: %w", err)
	}
	if !h.Response {
		return Response{}, errNotResponse
	}
	resp := Response{Truncated: h.Truncated}
	if h.RCode != dnsmessage.RCodeSuccess {
		// Truncation only means "retry larger" when the answer was cut
		// short by size. A refused or nonexistent name is not a truncation
		// however the resolver set the bit, and retrying it with EDNS would
		// spend a poll to be told the same thing.
		resp.Truncated = false
		return resp, fmt.Errorf("beacon: %s", rcode(h.RCode))
	}
	qs, err := p.AllQuestions()
	if err != nil {
		return resp, fmt.Errorf("beacon: %w", err)
	}
	if len(qs) == 0 {
		return resp, errNoQuestion
	}
	want := strings.ToLower(q.Name)
	if got := strings.TrimSuffix(strings.ToLower(qs[0].Name.String()), "."); got != want {
		return resp, fmt.Errorf("%w: %q, not %q", errForOther, got, q.Name)
	}
	answers, err := p.AllAnswers()
	if err != nil {
		return resp, fmt.Errorf("beacon: %w", err)
	}
	for _, a := range answers {
		txt, ok := a.Body.(*dnsmessage.TXTResource)
		if !ok {
			continue
		}
		// Only records owned by the name asked about. A wildcard or a
		// hijacking resolver can put other names in the answer section, and
		// a record for another name answers a question that was not asked.
		if got := strings.TrimSuffix(strings.ToLower(a.Header.Name.String()), "."); got != want {
			continue
		}
		// TXT character-strings concatenate in wire order, for the same
		// reason §16.5 gives for the carrier: a record longer than 255
		// bytes spans several, and the record is their concatenation.
		resp.Records = append(resp.Records, strings.Join(txt.TXT, ""))
	}
	return resp, nil
}

// rcode names a DNS response code as it appears in logs.
func rcode(c dnsmessage.RCode) string {
	switch c {
	case dnsmessage.RCodeFormatError:
		return "FORMERR"
	case dnsmessage.RCodeServerFailure:
		return "SERVFAIL"
	case dnsmessage.RCodeNameError:
		return "NXDOMAIN"
	case dnsmessage.RCodeNotImplemented:
		return "NOTIMP"
	case dnsmessage.RCodeRefused:
		return "REFUSED"
	}
	return fmt.Sprintf("RCODE(%d)", uint16(c))
}
