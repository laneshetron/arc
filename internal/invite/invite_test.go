package invite

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
)

func sample() *Invite {
	v := &Invite{Carriers: CarrierUDP | CarrierTLS, Addr: netip.MustParseAddr("203.0.113.7"), UDPPort: 4433, TLSPort: 443,
		Fingerprint: "chrome", ServerName: "s3.amazonaws.com"}
	for i := range v.RelayKey {
		v.RelayKey[i] = byte(i)
	}
	copy(v.ID[:], "invite01")
	copy(v.Secret[:], "0123456789abcdef")
	return v
}

func TestRoundTrip(t *testing.T) {
	for _, v := range []*Invite{
		sample(),
		{Carriers: CarrierUDP, Addr: netip.MustParseAddr("2001:db8::1"), UDPPort: 1},
		{Carriers: CarrierFront, Addr: netip.MustParseAddr("192.0.2.1"), FrontPort: 443, ServerName: "front.example"},
	} {
		s := v.String()
		got, err := Parse(" " + s + "\n")
		if err != nil {
			t.Fatalf("%s: %v", s, err)
		}
		if *got != *v {
			t.Errorf("round trip:\n got %+v\nwant %+v", got, v)
		}
	}
	// About 120 characters with UDP, TLS and a 16-byte cover (§3.3).
	if n := len(sample().String()); n > 130 {
		t.Errorf("invite is %d characters", n)
	}
}

func TestParseRejects(t *testing.T) {
	s := sample().String()
	// A transcription error: one character changed.
	b := []byte(s)
	i := len(Prefix) + 10
	if b[i] == 'A' {
		b[i] = 'B'
	} else {
		b[i] = 'A'
	}
	if _, err := Parse(string(b)); err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Errorf("mistyped invite: %v", err)
	}
	for _, bad := range []string{"", "arc2:" + s[len(Prefix):], s[:len(s)-4], "arc1:!!!"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) succeeded", bad)
		}
	}
	for _, v := range []*Invite{
		{Carriers: 0, Addr: netip.MustParseAddr("192.0.2.1")},
		{Carriers: CarrierTLS | CarrierFront, Addr: netip.MustParseAddr("192.0.2.1"), TLSPort: 1, FrontPort: 1, ServerName: "x"},
		{Carriers: CarrierTLS, Addr: netip.MustParseAddr("192.0.2.1"), TLSPort: 443},
		{Carriers: CarrierUDP, Addr: netip.MustParseAddr("192.0.2.1")},
		{Carriers: CarrierUDP, Addr: netip.MustParseAddr("192.0.2.1"), UDPPort: 1, Fingerprint: "netscape"},
	} {
		if v.Validate() == nil {
			t.Errorf("valid: %+v", v)
		}
	}
}

func TestEnrollmentCredential(t *testing.T) {
	e := &Enrollment{Token: NewToken(), Name: "laptop"}
	copy(e.ID[:], "invite01")
	copy(e.Secret[:], "0123456789abcdef")
	c := e.Credential()
	if !IsEnrollment(c) || IsEnrollment(e.Token) {
		t.Fatal("enrollment not told apart from a token")
	}
	got, err := ParseEnrollment(c)
	if err != nil || got.ID != e.ID || got.Secret != e.Secret || !bytes.Equal(got.Token, e.Token) || got.Name != e.Name {
		t.Fatalf("round trip: %+v %v", got, err)
	}
	if len(e.Token) != 43 {
		t.Errorf("token is %d characters", len(e.Token))
	}
	for _, bad := range [][]byte{c[:len(c)-1], append(c, 0), []byte(enrollMagic)} {
		if _, err := ParseEnrollment(bad); err == nil {
			t.Errorf("ParseEnrollment(%x) succeeded", bad)
		}
	}
}
