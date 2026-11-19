package beacon

import (
	"errors"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// TestFeedbackFindings is the acceptance check for the four review findings
// on #67 and #70. Each subtest fails on the code as it was merged.
func TestFeedbackFindings(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	pub, priv := testKey(t)

	t.Run("P2 #70 a foreign RCODE does not end the lookup", func(t *testing.T) {
		q, err := NewQuery("example.net", ProfileBootstrap, detRand(1))
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
		hdr.RCode = dnsmessage.RCodeNameError
		hdr.ID = q.ID + 1
		if _, err := ParseAnswer(q, answerWith(t, q, hdr, qs[0].Name, "")); !errors.Is(err, errForOther) {
			t.Fatalf("got %v, want errForOther", err)
		}
	})

	t.Run("P2 #70 b1 and b2 are distinguishable and domain-separated", func(t *testing.T) {
		b1, err := NewNamedQuery("b1", testZone, ProfileBootstrap, detRand(1))
		if err != nil {
			t.Fatal(err)
		}
		if b1.Suffix == Suffix(testZone) {
			t.Fatal("a named query built the unnamed suffix")
		}
		content, err := Encode(oneRelay(t, now), b1.Suffix, priv)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Decode(content, NamedSuffix("b2", testZone), pub, now); err == nil {
			t.Fatal("b1's record verified as b2's")
		}
		if _, err := Decode(content, b1.Suffix, pub, now); err != nil {
			t.Fatalf("b1's own record failed: %v", err)
		}
	})

	t.Run("P2 #70 the EDNS limit accounts for the response OPT", func(t *testing.T) {
		q, err := NewQuery("example.net", ProfileEDNS, detRand(1))
		if err != nil {
			t.Fatal(err)
		}
		if got := maxSigned(t, q); got != 409 {
			t.Fatalf("max signed %d, want 409", got)
		}
	})

	t.Run("P2 #67 the encoder refuses a record the decoder rejects", func(t *testing.T) {
		b := oneRelay(t, now)
		b.Relays[0].Endpoints = append(b.Relays[0].Endpoints,
			Endpoint{Kind: EndpointKind(7), Port: 1})
		if _, err := Encode(b, Suffix(testZone), priv); err == nil {
			t.Fatal("encoded an unknown endpoint kind")
		}
		b = oneRelay(t, now)
		b.Names = []string{"CDN.Example.ORG"}
		if _, err := Encode(b, Suffix(testZone), priv); err == nil {
			t.Fatal("encoded a cover name that is not lowercase ASCII")
		}
	})
}
