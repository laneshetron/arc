// Package portal classifies a captive network's admission state
// (spec/captive-portals.md §3–§4): whether a portal exists, whether the user
// has passed it, and whether ARC can tell at all.
//
// The classifier is pure. It consumes Evidence and holds the per-attachment
// history of §4.3, so every row of the classification table is a test case
// and no test needs a network. probe.go supplies the Evidence.
package portal

import "net/url"

// State is the admission state of one network attachment (§3).
type State uint8

const (
	// StateUnknown is the startup state, and the state after detection
	// cannot conclude: a portal that intercepts TLS, or a network that drops
	// the connectivity endpoints, cannot be classified from outside.
	//
	// Carrier policy for it is "open, with a warning" (§6.3) — refusing to
	// start on "probably a portal" would strand users on ordinary networks
	// with broken middleboxes.
	StateUnknown State = iota

	// StateNone means no portal has ever been seen on this attachment, so
	// the network is open. It is distinct from StateAuthenticated only by
	// history: the two look identical to a probe (§4.3.1).
	StateNone

	// StateUnauthenticated means a portal exists and the user has not
	// passed it. Carriers must not open (§6.1): a handshake through a portal
	// cannot succeed, and on a metered link costs the user money.
	StateUnauthenticated

	// StateAuthenticated means a portal exists and the user has passed it.
	// Carriers open, and the expiry keepalive of §5 runs.
	StateAuthenticated
)

func (s State) String() string {
	switch s {
	case StateNone:
		return "none"
	case StateUnauthenticated:
		return "unauthenticated"
	case StateAuthenticated:
		return "authenticated"
	}
	return "unknown"
}

// BlocksCarriers reports whether carriers must stay closed in this state.
// Only StateUnauthenticated does: the connection cannot succeed there, and
// the other three all open (§6).
func (s State) BlocksCarriers() bool { return s == StateUnauthenticated }

// CheckKind is what probe A's connectivity endpoint did (§4.1).
type CheckKind uint8

const (
	// CheckNoAnswer is no usable response: a timeout, a refusal, a transport
	// error.
	CheckNoAnswer CheckKind = iota

	// CheckPass means the endpoint answered exactly as its profile declares
	// — status and, where the profile fixes one, body (§4.1).
	CheckPass

	// CheckRedirect means a 3xx. Any redirect is positive portal evidence,
	// whether or not its target is alive (§4.5): a dead target costs the
	// user a URL, not the verdict.
	CheckRedirect

	// CheckMismatch means the endpoint answered, but not as its profile
	// declares and not with a redirect: a revised success text, a gateway
	// 503, an injected error page. On its own this is not portal evidence
	// (§4.3.2).
	CheckMismatch
)

func (k CheckKind) String() string {
	switch k {
	case CheckPass:
		return "pass"
	case CheckRedirect:
		return "redirect"
	case CheckMismatch:
		return "mismatch"
	}
	return "no-answer"
}

// DNSVerdict is probe B's reading of the physical link's resolver (§4.4).
// It is tri-state because a stub-only or DoH-only host has no upstream to
// ask, and "could not measure" is not "honest".
type DNSVerdict uint8

const (
	// DNSUnmeasured means no upstream was discoverable, or the probe did not
	// run. The state then rests on probe A alone (§4.4).
	DNSUnmeasured DNSVerdict = iota

	// DNSClean means the answer was not categorically implausible. Answers
	// legitimately vary by geography and resolver, so a different public
	// address is not evidence of anything.
	DNSClean

	// DNSAnomalous means the answer was categorically implausible for a
	// public name — a private, loopback, link-local or reserved address, or
	// the portal host's own address.
	//
	// It is suspicious, never proof: corporate split-horizon policy, a
	// filtering resolver and an upstream sinkhole all produce it with no
	// portal present (§4.3.2).
	DNSAnomalous
)

func (v DNSVerdict) String() string {
	switch v {
	case DNSClean:
		return "clean"
	case DNSAnomalous:
		return "anomalous"
	}
	return "unmeasurable"
}

// Evidence is one round of detection: what probes A, B and the platform saw.
type Evidence struct {
	// Check is probe A's outcome.
	Check CheckKind

	// Redirect is a 3xx's Location, retained only when its target served a
	// page (probe C, §4.5). An empty Redirect with CheckRedirect means the
	// interception is proven but no usable login URL was found.
	Redirect string

	// LoginForm reports that the response body carried login form markers
	// (§4.3.2): what distinguishes a portal page served by the connectivity
	// host itself from an endpoint that merely changed its text.
	LoginForm bool

	// Platform reports that the platform's own captive-portal API named a
	// portal (§4.5). Where it is available it is better evidence than an
	// HTTP check, but it does not replace A and B.
	Platform bool

	// DNS is probe B's verdict.
	DNS DNSVerdict
}

// portals reports whether the evidence proves a portal exists. Only positive
// evidence counts (§4.3.2): a mismatch, a timeout or an anomalous DNS answer
// on its own does not, because all of those have innocent explanations that
// would otherwise cost the user every carrier.
func (e Evidence) portals() bool {
	return e.Platform || e.Check == CheckRedirect || e.LoginForm
}

// timeoutsToUnknown is how many consecutive unanswered rounds make the
// network unreachable rather than merely unclassified. §5.1: "three
// timeouts, not one" — a single lost request is an aircraft handover or a
// congested AP, and the client should not tell a user their portal expired
// because one packet was lost.
const timeoutsToUnknown = 3

// Classifier holds the per-attachment history of §4.3 and decides the state
// from each round of Evidence.
//
// The history is evidence, not a state ordering: PortalSeen records that a
// portal has been identified here at any time, which is what distinguishes
// StateNone from StateAuthenticated when a probe passes (§4.3.1). It is a
// boolean precisely because "a portal has been seen here" does not decay into
// a position in an ordering.
type Classifier struct {
	// PortalSeen and PortalURL persist per network attachment and survive a
	// tunnel restart on it.
	//
	// PortalURL is the transient login URL in full — scheme, host, path and
	// query — because portals need their exact path ("/login?ref=…") and a
	// user sent to the bare host often lands somewhere that does not work.
	// §4.7's redaction applies at the diagnostics boundary, not here: the
	// user must see the real URL (§4.7).
	PortalSeen bool
	PortalURL  string

	// DNS is the last probe-B verdict, for reporting.
	DNS DNSVerdict

	state    State
	timeouts int
}

// Host is the portal's host, for logs and status lines that should not carry a
// token-bearing query (§4.7).
func (c *Classifier) Host() string { return hostOf(c.PortalURL) }

// Resume restores a previous run's history for this attachment: the state it
// last reported and whether a portal has ever been identified here.
//
// **Nothing calls it in production yet, and that is a deliberate deferral.**
// §4.3 makes portal_seen persistent per network attachment, and the cache key
// that requires is the profiler's local-layer identity (SSID or gateway
// identity, network-profiling.md §2) — which does not exist in this tree.
// Keying it on the interface name instead would carry a hotel's portal verdict
// onto the same machine's home network, which is the opposite of "per
// attachment" and would mislabel a healthy network as authenticated. Until the
// profiler supplies the key, a restart on an already-passed portal reports
// StateNone instead of StateAuthenticated; the two differ only in label, since
// carriers open and the expiry check runs in both (§4.3.1), so the cost of the
// deferral is a label, not a behaviour.
//
// The URL is never part of the history: it is transient, and one carried across
// a restart goes stale — a portal that has since moved would still be
// advertised.
func (c *Classifier) Resume(state State, seen bool) {
	c.state, c.PortalSeen, c.PortalURL = state, seen, ""
	c.timeouts = 0
}

// State is the current verdict.
func (c *Classifier) State() State { return c.state }

// Observe applies one round of evidence and returns the new state.
//
// The order of the tests is the order of §4.3's table, and it matters:
// positive portal evidence wins over a passing check, and a passing check wins
// over a DNS anomaly. Positive evidence also wins over no answer at all — the
// platform's own API can name a portal when the HTTP probes cannot reach
// anything, and discarding that would ignore the best evidence available.
func (c *Classifier) Observe(ev Evidence) State {
	c.DNS = ev.DNS

	// Positive portal evidence first (§4.3.2). A redirect is proof even with a
	// dead target; a login form is proof even when the connectivity host
	// served it itself; the platform's API is proof when it says so, whether
	// or not the probes answered.
	if ev.portals() {
		c.PortalSeen = true
		c.timeouts = 0
		// The URL is transient evidence: set it when one is found, and clear it
		// when the portal no longer offers one, so a dead target does not leave
		// a stale link on screen (§4.5).
		if ev.Redirect != "" {
			c.PortalURL = ev.Redirect
		} else if ev.Check == CheckRedirect || ev.LoginForm {
			// Proven interception with no usable URL.
			c.PortalURL = ""
		}
		c.state = StateUnauthenticated
		return c.state
	}

	// No answer at all. Fewer than three rounds leave the state where it was,
	// because one lost probe is not evidence about the network.
	if ev.Check == CheckNoAnswer {
		c.timeouts++
		if c.timeouts >= timeoutsToUnknown {
			// PortalSeen is deliberately unchanged: being unable to reach the
			// probes says nothing about whether a portal exists (§4.3).
			c.state = StateUnknown
		}
		return c.state
	}
	c.timeouts = 0

	// The check passed and nothing proved a portal. Whether that means "open"
	// or "portal passed" is decided by history, because the two are
	// observationally identical (§4.3.1) — and on a genuine first encounter
	// with an already-passed portal, StateNone is genuinely all ARC can know.
	//
	// An anomalous DNS verdict alongside a passing check does not demote the
	// state. §4.3.2 requires an HTTP signal to corroborate DNS before it
	// counts, and a resolver that lies while the web works is a filtering
	// resolver rather than a portal. §5.1's transition table states the same
	// outcome: the path stays authenticated and the journal warns.
	if ev.Check == CheckPass {
		if c.PortalSeen {
			c.state = StateAuthenticated
		} else {
			c.state = StateNone
		}
		return c.state
	}

	// Answered, but not as declared and not a redirect. Not portal evidence,
	// so carriers open with a warning rather than being suppressed: a wrong
	// StateUnknown costs one failed handshake, a wrong
	// StateUnauthenticated costs the user all connectivity with a message to
	// log in to something that is not there (§4.3.2).
	c.state = StateUnknown
	return c.state
}

// hostOf returns the host of a redirect target, or "" when there is none.
func hostOf(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return u.Host
}

// LoginFormMarkers are the body markers that identify a login page (§4.3.2):
// a form asking for something only a portal asks for. The test is over form
// elements, not content, and is deliberately coarse — it only has to tell a
// login page from an endpoint that changed its success text.
var LoginFormMarkers = []string{
	"type=\"password\"",
	"type='password'",
	"name=\"voucher\"",
	"name='voucher'",
	"name=\"room\"",
	"name='room'",
	"name=\"seat\"",
	"name='seat'",
	"name=\"terms\"",
	"name='terms'",
	"accept_terms",
}
