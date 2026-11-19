package beacon

import (
	"strings"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// questionName reads the first question's name from an encoded message.
func questionName(t *testing.T, wire []byte) string {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(wire); err != nil {
		t.Fatalf("parse query: %v", err)
	}
	q, err := p.Question()
	if err != nil {
		t.Fatalf("parse question: %v", err)
	}
	return strings.TrimSuffix(q.Name.String(), ".")
}

// hasOPT reports whether a query carries an EDNS(0) OPT record.
func hasOPT(t *testing.T, wire []byte) bool {
	t.Helper()
	var p dnsmessage.Parser
	if _, err := p.Start(wire); err != nil {
		t.Fatalf("parse query: %v", err)
	}
	if err := p.SkipAllQuestions(); err != nil {
		t.Fatalf("skip questions: %v", err)
	}
	if err := p.SkipAllAnswers(); err != nil {
		t.Fatalf("skip answers: %v", err)
	}
	if err := p.SkipAllAuthorities(); err != nil {
		t.Fatalf("skip authorities: %v", err)
	}
	h, err := p.AdditionalHeader()
	if err != nil {
		// No additional section at all is the bootstrap profile.
		return false
	}
	return h.Type == dnsmessage.TypeOPT
}

// mustQuery builds a query for tests that need one but do not care how.
func mustQuery(t *testing.T, zone string, p Profile) Query {
	t.Helper()
	q, err := NewQuery(zone, p, detRand(1))
	if err != nil {
		t.Fatal(err)
	}
	return q
}

// replyTo answers the message wire with a TXT record owned by the name the
// message asked about.
func replyTo(t *testing.T, wire []byte, content string, truncated bool) []byte {
	t.Helper()
	return replyToName(t, wire, "", content, truncated)
}

// replyToName answers wire with a TXT record owned by ownerName, or by the
// message's own question when ownerName is empty.
func replyToName(t *testing.T, wire []byte, ownerName, content string, truncated bool) []byte {
	t.Helper()
	var p dnsmessage.Parser
	hdr, err := p.Start(wire)
	if err != nil {
		t.Fatalf("parse query: %v", err)
	}
	qs, err := p.AllQuestions()
	if err != nil {
		t.Fatalf("parse questions: %v", err)
	}
	owner := qs[0].Name
	if ownerName != "" {
		owner, err = dnsmessage.NewName(ownerName)
		if err != nil {
			t.Fatal(err)
		}
	}
	hdr.Response = true
	hdr.RecursionAvailable = true
	hdr.Truncated = truncated
	b := dnsmessage.NewBuilder(nil, hdr)
	b.EnableCompression()
	if err := b.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	for _, q := range qs {
		if err := b.Question(q); err != nil {
			t.Fatal(err)
		}
	}
	if content != "" || truncated {
		if err := b.StartAnswers(); err != nil {
			t.Fatal(err)
		}
		if content != "" {
			if err := b.TXTResource(dnsmessage.ResourceHeader{
				Name:  owner,
				Class: dnsmessage.ClassINET,
				TTL:   60,
			}, dnsmessage.TXTResource{TXT: chunk255(content)}); err != nil {
				t.Fatal(err)
			}
		}
	}
	msg, err := b.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return msg
}
