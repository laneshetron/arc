package portal

import "testing"

// observe runs one round from a fresh classifier with the given history.
func observe(seen bool, ev Evidence) State {
	var c Classifier
	c.Resume(StateUnknown, seen, "")
	return c.Observe(ev)
}

// TestClassificationTable walks the rows of spec §4.3's transition table.
// One case per row, so a change to the table that the code does not follow
// fails here rather than in the field.
func TestClassificationTable(t *testing.T) {
	for _, tc := range []struct {
		name string
		seen bool
		ev   Evidence
		want State
	}{
		// "passing check, DNS honest" — and the pair that motivates the whole
		// history field: the same observation means two different things.
		{"passing check, no history", false, Evidence{Check: CheckPass, DNS: DNSClean}, StateNone},
		{"passing check, portal seen before", true, Evidence{Check: CheckPass, DNS: DNSClean}, StateAuthenticated},
		{"passing check, seen via DNS only", true, Evidence{Check: CheckPass, DNS: DNSClean}, StateAuthenticated},

		// "confirmed portal (redirect / login form / platform API)".
		{"redirect to a live login host", false, Evidence{Check: CheckRedirect, Redirect: "https://portal.example.net/login"}, StateUnauthenticated},
		{"login form served by the endpoint itself", false, Evidence{Check: CheckMismatch, LoginForm: true}, StateUnauthenticated},
		{"platform API names a portal", false, Evidence{Check: CheckMismatch, Platform: true}, StateUnauthenticated},

		// "unexplained mismatch (bad status, wrong body, 503)" — not portal
		// evidence, so carriers open with a warning.
		{"endpoint changed its success text", false, Evidence{Check: CheckMismatch, DNS: DNSClean}, StateUnknown},
		{"gateway 503", true, Evidence{Check: CheckMismatch, DNS: DNSClean}, StateUnknown},

		// "anomalous DNS, uncorroborated" — suspicious, never proof.
		{"DNS anomalous under a passing check", false, Evidence{Check: CheckPass, DNS: DNSAnomalous}, StateNone},
		{"DNS anomalous under a passing check, portal seen", true, Evidence{Check: CheckPass, DNS: DNSAnomalous}, StateAuthenticated},
		{"DNS anomalous and the check mismatched", false, Evidence{Check: CheckMismatch, DNS: DNSAnomalous}, StateUnknown},
		// "anomalous DNS, corroborated by an HTTP signal" — the combination
		// is what counts, which the redirect row proves: the redirect is the
		// HTTP signal and DNS merely agrees.
		{"DNS anomalous and a redirect", false, Evidence{Check: CheckRedirect, Redirect: "https://portal.example.net/", DNS: DNSAnomalous}, StateUnauthenticated},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := observe(tc.seen, tc.ev); got != tc.want {
				t.Errorf("state = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestPortalSeenIsSetByPositiveEvidenceOnly checks that the history flag is
// raised by the same evidence that raises the state, and by nothing else —
// since it is what makes a later passing check mean "authenticated".
func TestPortalSeenIsSetByPositiveEvidenceOnly(t *testing.T) {
	for _, tc := range []struct {
		name string
		ev   Evidence
		want bool
	}{
		{"redirect", Evidence{Check: CheckRedirect, Redirect: "https://p.example/"}, true},
		{"login form", Evidence{Check: CheckMismatch, LoginForm: true}, true},
		{"platform", Evidence{Check: CheckMismatch, Platform: true}, true},
		{"passing check", Evidence{Check: CheckPass}, false},
		{"mismatch", Evidence{Check: CheckMismatch}, false},
		{"no answer", Evidence{Check: CheckNoAnswer}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var c Classifier
			c.Resume(StateUnknown, false, "")
			c.Observe(tc.ev)
			if c.PortalSeen != tc.want {
				t.Errorf("PortalSeen = %v, want %v", c.PortalSeen, tc.want)
			}
		})
	}
}

// TestDNSAnomalyAloneNeverSuppressesCarriers is the §4.3.2 guarantee: an
// anomalous resolver answer must not cost the user every carrier, because a
// corporate split-horizon resolver produces one with no portal in sight.
func TestDNSAnomalyAloneNeverSuppressesCarriers(t *testing.T) {
	got := observe(false, Evidence{Check: CheckPass, DNS: DNSAnomalous})
	if got.BlocksCarriers() {
		t.Fatalf("state %v blocks carriers on an anomalous DNS answer alone", got)
	}
}

// TestThreeTimeoutsNotOne covers §5.1: one lost probe leaves the state alone,
// three make the network unreachable.
func TestThreeTimeoutsNotOne(t *testing.T) {
	var c Classifier
	c.Resume(StateAuthenticated, true, "portal.example.net")

	for i := 1; i <= timeoutsToUnknown-1; i++ {
		if got := c.Observe(Evidence{Check: CheckNoAnswer}); got != StateAuthenticated {
			t.Fatalf("after %d timeouts state = %v, want it unchanged", i, got)
		}
	}
	if got := c.Observe(Evidence{Check: CheckNoAnswer}); got != StateUnknown {
		t.Fatalf("after %d timeouts state = %v, want unknown", timeoutsToUnknown, got)
	}
	// Being unable to reach the probes says nothing about whether a portal
	// exists, so the history must survive.
	if !c.PortalSeen {
		t.Error("PortalSeen was cleared by timeouts")
	}
}

// TestTimeoutCounterResets checks that a single answer between timeouts does
// not accumulate towards the unknown threshold — otherwise a flaky network
// would eventually look unreachable across hours of good service.
func TestTimeoutCounterResets(t *testing.T) {
	var c Classifier
	c.Resume(StateAuthenticated, true, "")

	for i := 0; i < 10; i++ {
		c.Observe(Evidence{Check: CheckNoAnswer})
		c.Observe(Evidence{Check: CheckPass, DNS: DNSClean})
	}
	if got := c.State(); got != StateAuthenticated {
		t.Fatalf("state = %v after alternating timeouts and passes, want authenticated", got)
	}
	// And one timeout now must not tip it: the counter was reset.
	if got := c.Observe(Evidence{Check: CheckNoAnswer}); got != StateAuthenticated {
		t.Fatalf("state = %v after a single timeout following a pass, want unchanged", got)
	}
}

// TestExpiryAndRecovery covers the authenticated → unauthenticated →
// authenticated cycle of §5.1, which is what the expiry keepalive exists for.
func TestExpiryAndRecovery(t *testing.T) {
	var c Classifier
	c.Resume(StateAuthenticated, true, "portal.example.net")

	// The grant expires: the portal redirects again.
	if got := c.Observe(Evidence{Check: CheckRedirect, Redirect: "https://portal.example.net/login?ref=1"}); got != StateUnauthenticated {
		t.Fatalf("state = %v after expiry, want unauthenticated", got)
	}
	if got := c.PortalHost; got != "portal.example.net" {
		t.Errorf("PortalHost = %q, want the redirect host", got)
	}

	// The user logs in: the login poll sees a passing check, and the history
	// is what makes that "authenticated" rather than "none".
	if got := c.Observe(Evidence{Check: CheckPass, DNS: DNSClean}); got != StateAuthenticated {
		t.Fatalf("state = %v after login, want authenticated", got)
	}
}

// TestRedirectToDeadHostStillCounts is §4.5: interception is proven even when
// there is no usable URL to show, because StateUnknown would open carriers
// into a portal.
func TestRedirectToDeadHostStillCounts(t *testing.T) {
	var c Classifier
	c.Resume(StateUnknown, false, "")
	// A redirect whose target did not serve a page: Redirect is empty, but
	// the check kind still says the network redirected.
	got := c.Observe(Evidence{Check: CheckRedirect})
	if got != StateUnauthenticated {
		t.Fatalf("state = %v, want unauthenticated even with no usable URL", got)
	}
	if c.PortalHost != "" {
		t.Errorf("PortalHost = %q, want empty when the target is dead", c.PortalHost)
	}
	if !c.PortalSeen {
		t.Error("PortalSeen should be set by a redirect with a dead target")
	}
}

// TestResumeKeepsExpiryMonitor is §4.3.1's practical benefit: a restart on
// the same attachment keeps the monitor, so a grant that expires after a
// restart is still caught.
func TestResumeKeepsExpiryMonitor(t *testing.T) {
	var c Classifier
	c.Resume(StateAuthenticated, true, "portal.example.net")
	if got := c.Observe(Evidence{Check: CheckRedirect}); got != StateUnauthenticated {
		t.Fatalf("state = %v, want the resumed attachment to notice expiry", got)
	}
}

// TestResumeFreshAttachmentIsNone is the same benefit's limit: with no
// history, a passing check is StateNone, because an already-passed portal is
// indistinguishable from an open network on first contact.
func TestResumeFreshAttachmentIsNone(t *testing.T) {
	var c Classifier
	c.Resume(StateUnknown, false, "")
	if got := c.Observe(Evidence{Check: CheckPass, DNS: DNSClean}); got != StateNone {
		t.Fatalf("state = %v, want none on a fresh attachment", got)
	}
}

func TestBlocksCarriers(t *testing.T) {
	for _, tc := range []struct {
		s    State
		want bool
	}{
		{StateUnknown, false},
		{StateNone, false},
		{StateAuthenticated, false},
		{StateUnauthenticated, true},
	} {
		if got := tc.s.BlocksCarriers(); got != tc.want {
			t.Errorf("%v.BlocksCarriers() = %v, want %v", tc.s, got, tc.want)
		}
	}
}

func TestStateStrings(t *testing.T) {
	// These appear in the journal and on the status line, so they are part of
	// the observable interface rather than an implementation detail.
	for _, tc := range []struct {
		s    State
		want string
	}{
		{StateUnknown, "unknown"},
		{StateNone, "none"},
		{StateUnauthenticated, "unauthenticated"},
		{StateAuthenticated, "authenticated"},
	} {
		if got := tc.s.String(); got != tc.want {
			t.Errorf("%d.String() = %q, want %q", tc.s, got, tc.want)
		}
	}
}
