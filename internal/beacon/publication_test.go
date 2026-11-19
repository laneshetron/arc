package beacon

import (
	"testing"
	"time"
)

// TestPublicationRows checks §3.2's table against encoded records: which
// deployment shapes fit the 512-byte bootstrap profile and which need
// EDNS(0). These are the limits that decide whether an operator's beacon
// reaches a client behind a resolver that sends no OPT record, so they are
// asserted from real encodings rather than recomputed by hand.
func TestPublicationRows(t *testing.T) {
	_, priv := testKey(t)
	now := time.Unix(1_800_000_000, 0)

	base := func() *Beacon { return oneRelay(t, now) }
	withFront := func() *Beacon {
		b := base()
		b.Relays[0].Endpoints = []Endpoint{
			{Kind: KindTLS, Port: 443},
			{Kind: KindUDP, Port: 4433},
			{Kind: KindFront, Port: 443, Domain: "cdn.example.net"},
		}
		return b
	}
	twoTLS := func(zone string) *Beacon {
		b := base()
		b.Names = nil
		b.Zones = []string{zone}
		b.Relays[0].Endpoints = []Endpoint{{Kind: KindTLS, Port: 443}}
		r2 := b.Relays[0]
		r2.Addr = r2.Addr.Next()
		b.Relays = append(b.Relays, r2)
		return b
	}
	nRelays := func(n int, names bool) *Beacon {
		b := base()
		if !names {
			b.Names = nil
		}
		for i := 1; i < n; i++ {
			r := b.Relays[0]
			r.Addr = r.Addr.Next()
			b.Relays = append(b.Relays, r)
		}
		return b
	}

	cases := []struct {
		label string
		b     *Beacon
		fits  bool
	}{
		// §3.2 (corrected): at the 155-byte bootstrap name the answer admits
		// a 243-byte signed record, which covers every legal shape up to
		// three relays with two endpoints and a cover name. Only the
		// four-relay record exceeds it.
		{"1 relay tls+udp, 1 name", base(), true},
		{"1 relay tls+udp+front, 1 name", withFront(), true},
		{"2 relays tls only, no names, _arc.x.io", twoTLS("_arc.x.io"), true},
		{"2 relays tls only, no names, _arc.example.net", twoTLS("_arc.example.net"), true},
		{"2 relays tls+udp, 1 name", nRelays(2, true), true},
		{"3 relays tls+udp, no names", nRelays(3, false), true},
		{"4 relays tls+udp, no names", nRelays(4, false), false},
	}
	for _, c := range cases {
		t.Run(c.label, func(t *testing.T) {
			content, err := Encode(c.b, Suffix(testZone), priv)
			if err != nil {
				t.Fatal(err)
			}
			// Measured on a real answer to a real bootstrap query, rather
			// than assumed from the query's nominal length: the earlier
			// version of this test computed 12+255+4+12+1+content, which
			// both used the wrong query length and ignored name compression.
			q, err := NewQuery(testZone, ProfileBootstrap, detRand(1))
			if err != nil {
				t.Fatal(err)
			}
			answer := len(answerFor(t, q, content))
			if got := answer <= q.AnswerCap; got != c.fits {
				t.Fatalf("answer %d B (cap %d): fits=%v, spec §3.2 says %v (signed %d)",
					answer, q.AnswerCap, got, c.fits, len(content))
			}
		})
	}
}
