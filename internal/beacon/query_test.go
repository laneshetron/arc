package beacon

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// detRand gives a deterministic byte stream so a query is reproducible.
func detRand(seed byte) func([]byte) (int, error) {
	return func(b []byte) (int, error) {
		for i := range b {
			b[i] = seed
			seed++
		}
		return len(b), nil
	}
}

// answerFor renders the response to q carrying a record of n signed bytes,
// the way an authoritative server must: the question echoed, compression
// on, the content split into character-strings.
func answerFor(t *testing.T, q Query, content string) []byte {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(q.Wire)
	if err != nil {
		t.Fatal(err)
	}
	qs, err := p.AllQuestions()
	if err != nil {
		t.Fatal(err)
	}
	hdr.Response = true
	hdr.RecursionAvailable = true
	return answerWith(t, hdr, qs[0].Name, content)
}

func answerWith(t *testing.T, hdr dnsmessage.Header, name dnsmessage.Name, content string) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, hdr)
	// An answer must compress the question name to fit §3.2's caps at a
	// full-length question: uncompressed, the 255-byte name repeated in the
	// answer leaves no room for a record at all.
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(dnsmessage.Question{
		Name:  name,
		Type:  dnsmessage.TypeTXT,
		Class: dnsmessage.ClassINET,
	}); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := b.TXTResource(dnsmessage.ResourceHeader{
		Name:  name,
		Class: dnsmessage.ClassINET,
		TTL:   300,
	}, dnsmessage.TXTResource{TXT: chunk255(content)}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}

// signedRecord returns a TXT content of n signed bytes, which is what §3.2's
// limits are stated in: body plus the 64-byte signature.
func signedRecord(n int) string {
	return Prefix + base64.RawURLEncoding.EncodeToString(make([]byte, n))
}

// maxSigned is the largest signed record an answer to q can carry without
// exceeding q.AnswerCap.
func maxSigned(t *testing.T, q Query) int {
	t.Helper()
	lo, hi := 1, 4*ednsUDPSize
	for lo < hi {
		mid := (lo + hi + 1) / 2
		if len(answerFor(t, q, signedRecord(mid))) <= q.AnswerCap {
			lo = mid
		} else {
			hi = mid - 1
		}
	}
	return lo
}

// chunk255 splits a TXT record's content into character-strings, which is
// what a real server must do above 255 bytes.
func chunk255(s string) []string {
	var out []string
	for len(s) > 255 {
		out = append(out, s[:255])
		s = s[255:]
	}
	if s != "" || out == nil {
		out = append(out, s)
	}
	return out
}

func TestQuerySizesToTheAnswerItAdmits(t *testing.T) {
	// §3.2 states its limits in signed-record bytes: 168 for bootstrap, 408
	// for EDNS. The bootstrap figure is wrong — it is what a 255-byte name
	// admits, and padding to the limit loses 75 bytes of record for no gain.
	// The verified maxima are 243 and 417; the test pins what the code
	// produces so a change to either constant shows up here.
	for _, tc := range []struct {
		p    Profile
		zone string
		want int
	}{
		{ProfileBootstrap, "example.net", 243},
		{ProfileBootstrap, "x.io", 243},
		{ProfileBootstrap, "lifeline.example.org", 243},
		{ProfileEDNS, "example.net", 417},
	} {
		q, err := NewQuery(tc.zone, tc.p, detRand(7))
		if err != nil {
			t.Fatalf("%s %v: %v", tc.zone, tc.p, err)
		}
		if got := maxSigned(t, q); got != tc.want {
			t.Errorf("%s %v: largest record is %d B, want %d", tc.zone, tc.p, got, tc.want)
		}
	}
}

func TestQueryNameLength(t *testing.T) {
	// The name length is the crossover of the 3× rule and the resolver's
	// buffer, not the 255-byte limit: a bootstrap query is 171 B and an EDNS
	// one 282 B, which is what leaves room for the record.
	boot, err := NewQuery("example.net", ProfileBootstrap, detRand(1))
	if err != nil {
		t.Fatal(err)
	}
	if got := wireLen(boot.Name); got != 155 {
		t.Errorf("bootstrap name is %d wire bytes, want 155", got)
	}
	if len(boot.Wire) != 171 {
		t.Errorf("bootstrap query is %d B, want 171", len(boot.Wire))
	}
	edns, err := NewQuery("example.net", ProfileEDNS, detRand(1))
	if err != nil {
		t.Fatal(err)
	}
	if got := wireLen(edns.Name); got != 255 {
		t.Errorf("edns name is %d wire bytes, want 255", got)
	}
	if len(edns.Wire) != 282 {
		t.Errorf("edns query is %d B, want 282", len(edns.Wire))
	}
}

func TestQueryAnswerCap(t *testing.T) {
	// §3.2's 3× rule, as the code applies it: the smaller of the resolver's
	// buffer and 3× the query. At 171 B the 3× reaches 513, so the buffer
	// binds; at 282 B it reaches 846, which is under the 1232 advertised.
	boot, err := NewQuery("example.net", ProfileBootstrap, detRand(1))
	if err != nil {
		t.Fatal(err)
	}
	if boot.AnswerCap != 512 {
		t.Errorf("bootstrap cap %d, want 512", boot.AnswerCap)
	}
	edns, err := NewQuery("example.net", ProfileEDNS, detRand(1))
	if err != nil {
		t.Fatal(err)
	}
	if edns.AnswerCap != 846 {
		t.Errorf("edns cap %d, want 846", edns.AnswerCap)
	}
}

func TestQueryNamesAreDistinct(t *testing.T) {
	seen := make(map[string]bool)
	for seed := range byte(8) {
		q, err := NewQuery("example.net", ProfileBootstrap, detRand(seed*13))
		if err != nil {
			t.Fatal(err)
		}
		if seen[q.Name] {
			t.Fatalf("two queries share the name %q", q.Name)
		}
		seen[q.Name] = true
	}
}

func TestQueryNameIsLowercase(t *testing.T) {
	q, err := NewQuery("Example.NET.", ProfileBootstrap, detRand(3))
	if err != nil {
		t.Fatal(err)
	}
	if q.Name != strings.ToLower(q.Name) {
		t.Errorf("name %q is not lowercase", q.Name)
	}
	if strings.HasSuffix(q.Name, ".") {
		t.Errorf("name %q has a trailing dot", q.Name)
	}
	if !strings.HasSuffix(q.Name, "._arcb.example.net") {
		t.Errorf("name %q does not end in the beacon suffix", q.Name)
	}
	if q.Suffix != "_arcb.example.net" {
		t.Errorf("suffix %q", q.Suffix)
	}
}

func TestQueryPaddingLabelsAreMarked(t *testing.T) {
	q, err := NewQuery("example.net", ProfileBootstrap, detRand(4))
	if err != nil {
		t.Fatal(err)
	}
	labels := strings.Split(q.Name, ".")
	if len(labels) < 3 {
		t.Fatalf("name %q has %d labels", q.Name, len(labels))
	}
	// §2.2.1: `0` and `1` are outside the base32 alphabet, which is what
	// makes a padding label distinguishable from data without a length
	// prefix. Every label between the nonce and the suffix must therefore
	// start with `0`, and none may be a bare marker.
	for _, l := range labels[1 : len(labels)-3] {
		if !strings.HasPrefix(l, "0") {
			t.Errorf("padding label %q is not marked", l)
		}
		if len(l) < 2 || len(l) > maxLabel {
			t.Errorf("padding label %q is %d bytes, want 2..63", l, len(l))
		}
	}
	// The nonce is the first label and must not look like padding.
	if strings.HasPrefix(labels[0], "0") || len(labels[0]) != 13 {
		t.Errorf("nonce label %q", labels[0])
	}
}

func TestQueryProfileShape(t *testing.T) {
	boot, err := NewQuery("example.net", ProfileBootstrap, detRand(5))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	h, err := p.Start(boot.Wire)
	if err != nil {
		t.Fatal(err)
	}
	if !h.RecursionDesired {
		t.Error("query does not set RD")
	}
	if h.Response {
		t.Error("query is marked as a response")
	}
	qs, err := p.AllQuestions()
	if err != nil {
		t.Fatal(err)
	}
	if len(qs) != 1 {
		t.Fatalf("%d questions, want 1", len(qs))
	}
	if qs[0].Type != dnsmessage.TypeTXT || qs[0].Class != dnsmessage.ClassINET {
		t.Errorf("question is %v/%v", qs[0].Type, qs[0].Class)
	}
	if n := strings.TrimSuffix(qs[0].Name.String(), "."); n != boot.Name {
		t.Errorf("question name %q, want %q", n, boot.Name)
	}
	// The bootstrap profile carries no OPT record: it is the query that
	// fits a resolver with no EDNS(0) support.
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllAnswers(); err != nil {
		t.Fatal(err)
	}
	if err := p.SkipAllAuthorities(); err != nil {
		t.Fatal(err)
	}
	if _, err := p.AdditionalHeader(); !errors.Is(err, dnsmessage.ErrSectionDone) {
		t.Errorf("bootstrap profile has an additional: %v", err)
	}
}

func TestQueryEDNSAdvertises1232(t *testing.T) {
	q, err := NewQuery("example.net", ProfileEDNS, detRand(6))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	if _, err := p.Start(q.Wire); err != nil {
		t.Fatal(err)
	}
	for _, skip := range []func() error{p.SkipAllQuestions, p.SkipAllAnswers, p.SkipAllAuthorities} {
		if err := skip(); err != nil {
			t.Fatal(err)
		}
	}
	h, err := p.AdditionalHeader()
	if err != nil {
		t.Fatalf("edns profile has no OPT record: %v", err)
	}
	if h.Type != dnsmessage.TypeOPT {
		t.Fatalf("additional is %v, want OPT", h.Type)
	}
	// RFC 6891 §6.1.2: the requester's payload size lives in the class
	// field. This is the whole point of the EDNS profile, so it is asserted
	// rather than assumed.
	if got := uint16(h.Class); got != ednsUDPSize {
		t.Errorf("OPT advertises %d, want %d", got, ednsUDPSize)
	}
}

func TestPadNameNeverExceedsTheLimit(t *testing.T) {
	// Every remainder class of the whole-label division must land at or
	// under the limit, and the small ones must still produce a valid name.
	nonce := "aaaaaaaaaaaaa"
	for _, suffix := range []string{"_arcb.x.io", "_arcb.example.net", "_arcb.lifeline.example.org"} {
		for want := wireLen(nonce+"."+suffix) + 1; want <= maxName; want++ {
			name, err := padName(nonce, suffix, want)
			if err != nil {
				t.Fatalf("%s want %d: %v", suffix, want, err)
			}
			if got := wireLen(name); got > want {
				t.Fatalf("%s want %d: got %d B", suffix, want, got)
			}
			for _, l := range strings.Split(name, ".") {
				if len(l) > maxLabel {
					t.Fatalf("%s want %d: label %d bytes", suffix, want, len(l))
				}
				if l == "" {
					t.Fatalf("%s want %d: empty label in %q", suffix, want, name)
				}
				if l[0] == '0' && len(l) < 2 {
					t.Fatalf("%s want %d: bare marker label in %q", suffix, want, name)
				}
			}
			if _, err := dnsmessage.NewName(name + "."); err != nil {
				t.Fatalf("%s want %d: name does not parse: %v", suffix, want, err)
			}
		}
	}
}

func TestPadSplitSpendsEveryByte(t *testing.T) {
	// padSplit is what makes the padding exact rather than approximate; an
	// off-by-one here is a byte of answer space lost at every poll.
	for room := 0; room <= maxName; room++ {
		got := padSplit(room)
		sum := 0
		for _, n := range got {
			if n < 2 || n > maxLabel {
				t.Fatalf("room %d: label length %d", room, n)
			}
			sum += 1 + n // length byte plus contents
		}
		switch {
		case room <= 2:
			if len(got) != 0 {
				t.Fatalf("room %d: split %v, want none", room, got)
			}
		case sum != room:
			t.Fatalf("room %d: split %v spends %d", room, got, sum)
		}
	}
}

func TestParseAnswerExtractsTXT(t *testing.T) {
	q, err := NewQuery("example.net", ProfileBootstrap, detRand(9))
	if err != nil {
		t.Fatal(err)
	}
	msg := answerFor(t, q, "B1:first")
	resp, err := ParseAnswer(q, msg)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Truncated {
		t.Error("response marked truncated")
	}
	if len(resp.Records) != 1 || resp.Records[0] != "B1:first" {
		t.Errorf("records %q", resp.Records)
	}
}

func TestParseAnswerJoinsCharacterStrings(t *testing.T) {
	q, err := NewQuery("example.net", ProfileEDNS, detRand(10))
	if err != nil {
		t.Fatal(err)
	}
	// A record longer than 255 bytes arrives as several character-strings;
	// they concatenate in wire order and the result must equal what was
	// published, not any one piece.
	long := "B1:" + strings.Repeat("A", 400)
	resp, err := ParseAnswer(q, answerFor(t, q, long))
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Records) != 1 {
		t.Fatalf("%d records, want 1", len(resp.Records))
	}
	if resp.Records[0] != long {
		t.Errorf("record is %d chars, want %d", len(resp.Records[0]), len(long))
	}
}

func TestParseAnswerIgnoresNonTXTAndForeignNames(t *testing.T) {
	q, err := NewQuery("example.net", ProfileBootstrap, detRand(11))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(q.Wire)
	if err != nil {
		t.Fatal(err)
	}
	qs, err := p.AllQuestions()
	if err != nil {
		t.Fatal(err)
	}
	hdr.Response = true
	b := dnsmessage.NewBuilder(nil, hdr)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := b.Question(qs[0]); err != nil {
		t.Fatal(err)
	}
	if err := b.StartAnswers(); err != nil {
		t.Fatal(err)
	}
	// A sinkhole answers a TXT question with an A record, and a wildcard or
	// a hijacking resolver can answer with another name's TXT. Neither is an
	// answer to the question asked.
	if err := b.AResource(dnsmessage.ResourceHeader{
		Name:  qs[0].Name,
		Class: dnsmessage.ClassINET,
		TTL:   60,
	}, dnsmessage.AResource{A: [4]byte{10, 0, 0, 1}}); err != nil {
		t.Fatal(err)
	}
	foreign := dnsmessage.MustNewName("someone-else.example.net.")
	if err := b.TXTResource(dnsmessage.ResourceHeader{
		Name:  foreign,
		Class: dnsmessage.ClassINET,
		TTL:   60,
	}, dnsmessage.TXTResource{TXT: []string{"B1:forged"}}); err != nil {
		t.Fatal(err)
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ParseAnswer(q, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Records) != 0 {
		t.Errorf("foreign records accepted: %q", resp.Records)
	}
}

func TestParseAnswerTruncated(t *testing.T) {
	q, err := NewQuery("example.net", ProfileBootstrap, detRand(12))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(q.Wire)
	if err != nil {
		t.Fatal(err)
	}
	qs, err := p.AllQuestions()
	if err != nil {
		t.Fatal(err)
	}
	hdr.Response = true
	hdr.Truncated = true
	resp, err := ParseAnswer(q, answerWith(t, hdr, qs[0].Name, ""))
	if err != nil {
		t.Fatal(err)
	}
	// TC is not an error: it is §3.2's signal to retry with EDNS(0), so it
	// must survive parsing rather than be reported as a failure.
	if !resp.Truncated {
		t.Error("TC bit was dropped")
	}
}

func TestParseAnswerRcodes(t *testing.T) {
	q, err := NewQuery("example.net", ProfileBootstrap, detRand(13))
	if err != nil {
		t.Fatal(err)
	}
	var p dnsmessage.Parser
	hdr, err := p.Start(q.Wire)
	if err != nil {
		t.Fatal(err)
	}
	qs, err := p.AllQuestions()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		code dnsmessage.RCode
		want string
	}{
		{dnsmessage.RCodeNameError, "NXDOMAIN"},
		{dnsmessage.RCodeServerFailure, "SERVFAIL"},
		{dnsmessage.RCodeRefused, "REFUSED"},
		{dnsmessage.RCodeFormatError, "FORMERR"},
	} {
		h := hdr
		h.Response = true
		h.RCode = tc.code
		_, err := ParseAnswer(q, answerWith(t, h, qs[0].Name, "B1:ignored"))
		if err == nil {
			t.Fatalf("%v: no error", tc.code)
		}
		// §3.3 lists these as "no beacon this round"; the name in the error
		// is what a log shows, so it is what the test pins.
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: error %q does not mention %s", tc.code, err, tc.want)
		}
	}
}

func TestParseAnswerRejectsWrongQuestion(t *testing.T) {
	q, err := NewQuery("example.net", ProfileBootstrap, detRand(14))
	if err != nil {
		t.Fatal(err)
	}
	other, err := NewQuery("example.net", ProfileBootstrap, detRand(15))
	if err != nil {
		t.Fatal(err)
	}
	// Build an answer to `other`, then parse it as the answer to `q`. §3.3
	// matches on the name, so a response to a different nonce is refused
	// even though it is a well-formed answer to a question we did ask.
	msg := answerFor(t, other, "B1:wrong")
	if _, err := ParseAnswer(q, msg); !errors.Is(err, errForOther) {
		t.Errorf("got %v, want errForOther", err)
	}
}

func TestParseAnswerRejectsGarbage(t *testing.T) {
	q, err := NewQuery("example.net", ProfileBootstrap, detRand(16))
	if err != nil {
		t.Fatal(err)
	}
	for name, msg := range map[string][]byte{
		"empty":       {},
		"truncated":   {0, 0, 0, 0, 0},
		"not-a-query": []byte("this is not a DNS message at all"),
	} {
		if _, err := ParseAnswer(q, msg); err == nil {
			t.Errorf("%s: no error", name)
		}
	}
}

func TestParseAnswerRejectsQuery(t *testing.T) {
	q, err := NewQuery("example.net", ProfileBootstrap, detRand(17))
	if err != nil {
		t.Fatal(err)
	}
	// A query echoed back is not an answer, and taking it for one would let
	// a reflection of our own message count as a beacon.
	if _, err := ParseAnswer(q, q.Wire); !errors.Is(err, errNotResponse) {
		t.Errorf("got %v, want errNotResponse", err)
	}
}

func TestParseAnswerRoundTripsAPublishedBeacon(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	pub, priv := testKey(t)
	content, err := Encode(oneRelay(t, now), Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	q, err := NewQuery(testZone, ProfileBootstrap, detRand(18))
	if err != nil {
		t.Fatal(err)
	}
	// The whole point of sizing the query to the cap: a one-relay record has
	// to fit, or a cold client could never read one.
	msg := answerFor(t, q, content)
	if len(msg) > q.AnswerCap {
		t.Fatalf("answer is %d B, over the %d B cap", len(msg), q.AnswerCap)
	}
	resp, err := ParseAnswer(q, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Records) != 1 {
		t.Fatalf("%d records", len(resp.Records))
	}
	b, err := Decode(resp.Records[0], q.Suffix, pub, now)
	if err != nil {
		t.Fatalf("published record did not verify through the reader: %v", err)
	}
	if len(b.Relays) != 1 {
		t.Errorf("%d relays", len(b.Relays))
	}
}

func TestLargestBootstrapRecordFits(t *testing.T) {
	// A bootstrap answer must carry the biggest record §3.1 allows under the
	// publication rule, or a cold client is locked out of a legal deployment.
	// The rule is one relay; §3.2's biggest legal one-relay body is a relay
	// with all three endpoints and a cover name, which comes to 172 bytes.
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	_, priv := testKey(t)
	b := oneRelay(t, now)
	b.Names = []string{"cdn.example.org"}
	b.Relays[0].Endpoints = []Endpoint{
		{Kind: KindUDP, Port: 443},
		{Kind: KindTLS, Port: 443},
		{Kind: KindFront, Port: 443, Domain: "front.example.org"},
	}
	content, err := Encode(b, Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	q, err := NewQuery(testZone, ProfileBootstrap, detRand(19))
	if err != nil {
		t.Fatal(err)
	}
	msg := answerFor(t, q, content)
	if len(msg) > q.AnswerCap {
		t.Fatalf("a maximal one-relay record makes a %d-byte answer, over the %d B cap",
			len(msg), q.AnswerCap)
	}
	// And it must still verify, so the encoding path is exercised at the
	// size the sizing path promises.
	resp, err := ParseAnswer(q, msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(resp.Records[0], q.Suffix, priv.Public().(ed25519.PublicKey), now); err != nil {
		t.Fatal(err)
	}
}
