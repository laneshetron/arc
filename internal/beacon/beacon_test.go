package beacon

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// testKey returns a deterministic-ish key for a test.
func testKey(tb testing.TB) (ed25519.PublicKey, ed25519.PrivateKey) {
	tb.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		tb.Fatal(err)
	}
	return pub, priv
}

func relayKey(tb testing.TB) ed25519.PublicKey {
	tb.Helper()
	pub, _ := testKey(tb)
	return pub
}

// oneRelay is the deployment shape §3.1 gives sizes for: one relay with a
// tls and a udp endpoint, one cover name, one carrier zone.
func oneRelay(tb testing.TB, now time.Time) *Beacon {
	tb.Helper()
	return &Beacon{
		DNSAvailable: true,
		Published:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		Relays: []Relay{{
			Addr: netip.MustParseAddr("203.0.113.7"),
			Key:  relayKey(tb),
			Endpoints: []Endpoint{
				{Kind: KindTLS, Port: 443},
				{Kind: KindUDP, Port: 4433},
			},
		}},
		Names: []string{"cdn.example.net"},
		Zones: []string{"_arc.example.net"},
	}
}

const testZone = "example.net"

func TestRoundTrip(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	want := oneRelay(t, now)
	suffix := Suffix(testZone)

	content, err := Encode(want, suffix, priv)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(content, suffix, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.DNSAvailable || !got.Published.Equal(want.Published) || !got.NotAfter.Equal(want.NotAfter) {
		t.Fatalf("header mismatch: %+v", got)
	}
	if len(got.Relays) != 1 || got.Relays[0].Addr != want.Relays[0].Addr {
		t.Fatalf("relays: %+v", got.Relays)
	}
	if string(got.Relays[0].Key) != string(want.Relays[0].Key) {
		t.Fatal("relay key changed")
	}
	if len(got.Relays[0].Endpoints) != 2 ||
		got.Relays[0].Endpoints[0] != (Endpoint{Kind: KindTLS, Port: 443}) ||
		got.Relays[0].Endpoints[1] != (Endpoint{Kind: KindUDP, Port: 4433}) {
		t.Fatalf("endpoints: %+v", got.Relays[0].Endpoints)
	}
	if len(got.Names) != 1 || got.Names[0] != "cdn.example.net" {
		t.Fatalf("names: %v", got.Names)
	}
	if len(got.Zones) != 1 || got.Zones[0] != "_arc.example.net" {
		t.Fatalf("zones: %v", got.Zones)
	}
}

// TestSize pins the numbers §3.1 and §3.2 publish. A field added to the
// grammar invalidates them, so a change here means the spec's publication
// limits moved.
func TestSize(t *testing.T) {
	_, priv := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	content, err := Encode(oneRelay(t, now), Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(content, Prefix))
	if err != nil {
		t.Fatal(err)
	}
	// §3.1's field table ends with the 64-byte signature, so its "body
	// 153 B" is body plus signature; the body alone is 89.
	if len(raw) != 153 {
		t.Errorf("body+signature = %d B, spec §3.1 says 153", len(raw))
	}
	if body := len(raw) - ed25519.SignatureSize; body != 89 {
		t.Errorf("body = %d B, want 89 (153 with the signature)", body)
	}
	// §3.2's bootstrap profile pads the question name to 255 bytes, giving a
	// 271-byte query; the answer is 12 header + question + 12 answer header
	// + the TXT RDATA (a length byte plus the content).
	chars := len(content)
	if chars != 207 {
		t.Errorf("TXT content = %d chars, want 207 (spec says 208: it counts the RDATA length byte)", chars)
	}
	answer := 12 + 255 + 4 + 12 + 1 + chars
	if answer != 491 {
		t.Errorf("answer = %d B, want 491 (spec says 492)", answer)
	}
	if answer > 512 {
		t.Errorf("answer = %d B exceeds the 512-byte bootstrap profile", answer)
	}
}

// TestDomainSeparation checks that a record verifies only under the suffix
// it was signed for, which is what stops a replay under a name the operator
// does not control (§3.1).
func TestDomainSeparation(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	content, err := Encode(oneRelay(t, now), Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(content, Suffix("evil.example"), pub, now); !errors.Is(err, errSignature) {
		t.Fatalf("a record verified under another suffix: %v", err)
	}
	if _, err := Decode(content, Suffix("b2.example.net"), pub, now); !errors.Is(err, errSignature) {
		t.Fatalf("a record verified under another beacon name: %v", err)
	}
}

func TestWrongKey(t *testing.T) {
	pub, _ := testKey(t)
	_, otherPriv := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	content, err := Encode(oneRelay(t, now), Suffix(testZone), otherPriv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(content, Suffix(testZone), pub, now); !errors.Is(err, errSignature) {
		t.Fatalf("a record from another key verified: %v", err)
	}
}

func TestTamperedBody(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	content, err := Encode(oneRelay(t, now), Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(content, Prefix))
	if err != nil {
		t.Fatal(err)
	}
	raw[0] = 2 // version nibble inside the body, covered by the signature
	tampered := Prefix + base64.RawURLEncoding.EncodeToString(raw)
	if _, err := Decode(tampered, Suffix(testZone), pub, now); !errors.Is(err, errSignature) {
		t.Fatalf("a tampered record verified: %v", err)
	}
}

// TestExpiry is §3.4's rule for a beacon-only relay: past not_after it may
// not start a new connection, so Decode refuses.
func TestExpiry(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	b := oneRelay(t, now)
	content, err := Encode(b, Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Decode(content, Suffix(testZone), pub, b.NotAfter); !errors.Is(err, errTime) {
		t.Fatalf("a record verified at its not_after: %v", err)
	}
	if _, err := Decode(content, Suffix(testZone), pub, b.NotAfter.Add(-time.Second)); err != nil {
		t.Fatalf("a record refused one second before expiry: %v", err)
	}
}

// TestRejectsMalformed covers the shapes a hostile or broken intermediary can
// produce, all of which must be errors rather than panics (§16.5).
func TestRejectsMalformed(t *testing.T) {
	pub, priv := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	good, err := Encode(oneRelay(t, now), Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(strings.TrimPrefix(good, Prefix))
	if err != nil {
		t.Fatal(err)
	}
	resign := func(body []byte) string {
		sig := ed25519.Sign(priv, signedMessage(Suffix(testZone), body))
		return Prefix + base64.RawURLEncoding.EncodeToString(append(append([]byte{}, body...), sig...))
	}
	body := raw[:len(raw)-ed25519.SignatureSize]
	truncated := resign(body[:len(body)-1])

	cases := []struct {
		name    string
		content string
		want    error
	}{
		{"no prefix", strings.TrimPrefix(good, Prefix), errPrefix},
		{"not base64", Prefix + "!!!!", errBase64},
		{"empty", Prefix, errShort},
		{"too short", Prefix + base64.RawURLEncoding.EncodeToString(body[:8]), errShort},
		{"truncated body", truncated, errEndpoint},
		{"bad version", resign(append([]byte{2}, body[1:]...)), errVersion},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := Decode(c.content, Suffix(testZone), pub, now)
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
		})
	}
}

// TestFrontEndpointNeedsDomain checks the one endpoint kind that carries a
// payload: §3.5 requires the front's domain so a client knows the cover name.
func TestFrontEndpointNeedsDomain(t *testing.T) {
	_, priv := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	b := oneRelay(t, now)
	b.Relays[0].Endpoints = []Endpoint{{Kind: KindFront, Port: 443}}
	if _, err := Encode(b, Suffix(testZone), priv); !errors.Is(err, errEndpoint) {
		t.Fatalf("a front endpoint without a domain was encoded: %v", err)
	}
	b.Relays[0].Endpoints[0].Domain = "cdn.example.net"
	if _, err := Encode(b, Suffix(testZone), priv); err != nil {
		t.Fatalf("a front endpoint with a domain was refused: %v", err)
	}
}

// TestIPv4Only reflects that clients reach relays over IPv4 (§3.1).
func TestIPv4Only(t *testing.T) {
	_, priv := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	b := oneRelay(t, now)
	b.Relays[0].Addr = netip.MustParseAddr("2001:db8::1")
	if _, err := Encode(b, Suffix(testZone), priv); !errors.Is(err, errAddr) {
		t.Fatalf("an IPv6 relay address was encoded: %v", err)
	}
}

// TestLimits pins the counts the frozen grammar allows, since a beacon that
// exceeded them would not fit §3.2's publication profile.
func TestLimits(t *testing.T) {
	_, priv := testKey(t)
	now := time.Unix(1_800_000_000, 0)
	b := oneRelay(t, now)
	for len(b.Relays) <= MaxRelays {
		b.Relays = append(b.Relays, b.Relays[0])
	}
	if _, err := Encode(b, Suffix(testZone), priv); !errors.Is(err, errLimits) {
		t.Fatalf("%d relays were encoded: %v", len(b.Relays), err)
	}

	b = oneRelay(t, now)
	b.Zones = nil
	if _, err := Encode(b, Suffix(testZone), priv); !errors.Is(err, errLimits) {
		t.Fatalf("a record with no carrier zone was encoded: %v", err)
	}

	b = oneRelay(t, now)
	b.Names = make([]string, MaxNames+1)
	for i := range b.Names {
		b.Names[i] = "cdn.example.net"
	}
	if _, err := Encode(b, Suffix(testZone), priv); !errors.Is(err, errLimits) {
		t.Fatalf("%d names were encoded: %v", len(b.Names), err)
	}
}

func TestSuffix(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"example.net", "_arcb.example.net"},
		{"example.net.", "_arcb.example.net"},
		{"Example.NET", "_arcb.example.net"},
		{" example.net ", "_arcb.example.net"},
	} {
		if got := Suffix(c.in); got != c.want {
			t.Errorf("Suffix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
