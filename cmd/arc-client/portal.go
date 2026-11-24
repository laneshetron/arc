package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/laneshetron/arc/internal/carrier/sockopt"
	"github.com/laneshetron/arc/internal/portal"
	"github.com/laneshetron/arc/internal/tun"
)

// startupCheckTimeout bounds one attachment's startup check. It is generous —
// two probes with a 5 s HTTP timeout each plus upstream discovery — because
// the cost of cutting it short is a spurious "unknown", and the cost of
// waiting is a few seconds once at startup.
const startupCheckTimeout = 20 * time.Second

// probeGrace is how long the wait lets an in-flight probe report after the wait
// itself has been cancelled. Bounded and small: a login that completed at the
// deadline should count, and a stuck probe must not delay the exit.
const probeGrace = 250 * time.Millisecond

// checkPortal builds one detector per carrier attachment and classifies each.
//
// Per attachment, not one global verdict: an interface's bind says nothing
// about whether *that* link is captive. Testing only the first bind would mean
// captive Wi-Fi suppressing healthy cellular, and reversing the bind order
// would change the answer — so each attachment gets its own detector and its
// own state, and only an attachment that is confirmed captive is gated.
//
// It returns the detectors keyed by interface, the attachments a caller may
// still use (in -bind order), and every attachment as resolved, which is what
// carrierBinds needs to hand the carriers what the user asked for. An empty
// eligible list with no error means every attachment is captive.
func checkPortal(ctx context.Context, log *slog.Logger, cfg portal.Config, fullTunnel bool, binds []string, mark uint32) (map[string]*portal.Detector, []string, []attachment, error) {
	if !cfg.Mode.Enabled(fullTunnel) {
		// §8: -portal-check off sends no probes, and says so, because a client
		// that starts silently behind a portal looks broken.
		if cfg.Mode == portal.CheckOff {
			log.Info("captive portal detection is off (-portal-check off)")
		}
		return nil, binds, nil, nil
	}

	atts, err := attachments(fullTunnel, binds, log)
	if err != nil {
		return nil, nil, nil, err
	}

	detectors := make(map[string]*portal.Detector, len(atts))

	// Concurrently, not one after another: the probes are independent and each
	// can wait out a timeout, so serial detection would make startup cost the
	// sum of every attachment's worst case. Ctrl-C has to reach them too, which
	// is why the caller's context is threaded through.
	//
	// Each check gets its own bound. It is per check rather than around the
	// whole run so that a slow attachment classifies as unknown instead of
	// cancelling detection for every other attachment — and so that only real
	// cancellation (not our own deadline) reaches the ctx.Err test below.
	type outcome struct {
		iface string
		d     *portal.Detector
		state portal.State
	}
	results := make(chan outcome, len(atts))
	for _, a := range atts {
		go func(iface string) {
			opts := probeSocketOptions(fullTunnel, mark, iface)
			// One resolver per attachment answers both probe B and probe A's
			// hostname lookups: the HTTP checks must not consult the system
			// resolver once managed DNS points it at the tunnel (§4.1, §4.4).
			resolver := &portal.UpstreamResolver{Interface: iface, Sockopt: opts}
			p := portal.NewProber(resolver.Dialer(5 * time.Second))
			if cfg.ProbeURL != "" {
				p.Endpoints = []portal.Endpoint{cfg.Expect.Endpoint(cfg.ProbeURL)}
			}
			// Without a discoverable upstream, probe B reports unmeasurable,
			// which the state model already handles — so a host with no
			// resolvectl or a DoH-only network degrades to probe A alone
			// rather than failing.
			p.Resolver = resolver
			// Probe A resolves endpoint hostnames on the link too, once per
			// round: per-dial lookups would cost a dead upstream's full timeout
			// per endpoint before any HTTP was attempted.
			p.Rounds = resolver
			var c portal.Classifier
			d := &portal.Detector{
				Prober: p, Classifier: &c,
				// The interface is on every journal line from this detector.
				// Without it a two-attachment client's journal cannot tell a
				// captive Wi-Fi link from a healthy cellular one, which is the
				// whole question per-attachment detection exists to answer.
				Logger: log.With("interface", label(iface)),
			}
			checkCtx, cancel := context.WithTimeout(ctx, startupCheckTimeout)
			defer cancel()
			results <- outcome{iface: iface, d: d, state: d.Check(checkCtx)}
		}(a.iface)
	}

	ok := make(map[string]bool, len(atts))
	var blocked []string
	for range atts {
		r := <-results
		detectors[r.iface] = r.d
		if ctx.Err() != nil {
			// A cancelled probe is not evidence (§5.1). Nothing is known about
			// this attachment, so it is not eligible — but this is not a portal
			// verdict either, and the caller will see the context error.
			continue
		}
		if r.state.BlocksCarriers() {
			blocked = append(blocked, r.iface)
			continue
		}
		ok[r.iface] = true
	}
	if err := ctx.Err(); err != nil {
		return detectors, nil, atts, err
	}
	// In -bind order, not the order the concurrent checks happened to finish:
	// the first bind is the first carrier, and a run-to-run reshuffle would
	// change which link leads.
	eligible := make([]string, 0, len(atts))
	for _, a := range atts {
		if ok[a.iface] {
			eligible = append(eligible, a.iface)
		}
	}
	sort.Strings(blocked)
	for _, iface := range blocked {
		log.Info("attachment is behind a captive portal", "interface", label(iface))
	}
	return detectors, eligible, atts, nil
}

// attachment is one carrier attachment: what the user asked to bind, and the
// interface detection probes for it. They differ only for the default
// attachment (an empty bind), which detection must name so its probes stay off
// the TUN, but which carriers must keep unnamed where unnamed is what they were
// given — see carrierBinds.
type attachment struct {
	bind  string
	iface string
}

// carrierBinds turns the eligible attachments back into the binds the carriers
// should open, in the user's order.
//
// A default attachment is handed back as "" unless the carriers themselves need
// a name (full tunnel without policy routing, where client.OpenCarriers
// resolves the underlay the same way). Otherwise the name detection resolved
// would pin carriers that used to follow the default route to the interface it
// happened to be at startup, and a move from Wi-Fi to Ethernet would leave them
// behind.
func carrierBinds(atts []attachment, eligible []string, fullTunnel bool) []string {
	needName := fullTunnel && !tun.PolicyRouting
	ok := make(map[string]bool, len(eligible))
	for _, iface := range eligible {
		ok[iface] = true
	}
	out := make([]string, 0, len(eligible))
	seen := make(map[string]bool, len(atts))
	for _, a := range atts {
		if !ok[a.iface] {
			continue
		}
		b := a.iface
		if a.bind == "" && !needName {
			b = ""
		}
		if seen[b] {
			continue
		}
		seen[b] = true
		out = append(out, b)
	}
	return out
}

// attachments resolves the carrier attachments to physical interfaces. An empty
// -bind means "the default route's", and an entry left empty among explicit
// binds is resolved the same way `client.OpenCarriers` resolves it.
//
// The resolution is what keeps detection honest. With no socket marks (the
// macOS and non-policy-routing case) an unbound probe follows the default
// route, and once full-tunnel routing is installed that route is the TUN — so
// the probe would measure ARC's own tunnel instead of the network under it.
// Probe B needs the name too: it discovers an upstream per link (§4.4).
//
// Only where nothing else identifies the link is "" the right answer, which is
// Linux with policy routing: the mark keeps traffic on the physical link
// regardless of routing, and `tun.Underlay` returns "" there for that reason.
//
// Two entries that resolve to the same interface are one attachment: the
// default route's interface named again explicitly is still one link, and two
// detectors for it would race each other's verdicts.
func attachments(fullTunnel bool, binds []string, log *slog.Logger) ([]attachment, error) {
	if len(binds) == 0 {
		binds = []string{""}
	}
	// A missing default route is fatal only where the name is load-bearing.
	// Carrier opening fails the same way in the identical situation, so
	// reporting it here — before a TUN exists — is a clearer error, not a new
	// requirement.
	needName := fullTunnel && !tun.PolicyRouting

	out := make([]attachment, 0, len(binds))
	seen := make(map[string]bool, len(binds))
	for _, bind := range binds {
		iface := bind
		if bind == "" {
			underlay, err := underlayInterface()
			switch {
			case err != nil && needName:
				return nil, err
			case err == nil && underlay != "":
				iface = underlay
				log.Info("probing from the default route's interface", "interface", underlay)
			}
		}
		if seen[iface] {
			continue
		}
		seen[iface] = true
		out = append(out, attachment{bind: bind, iface: iface})
	}
	return out, nil
}

// underlayInterface is tun.Underlay, indirected so the default-attachment path
// can be tested without a live default route.
var underlayInterface = tun.Underlay

// label names an attachment for logs, where "" means the default route's.
func label(iface string) string {
	if iface == "" {
		return "default"
	}
	return iface
}

// probeSocketOptions returns the socket options that keep probe traffic on the
// physical link, matching what the carriers do.
//
// The mark is Linux-only and only meaningful once policy routing is installed:
// `sockopt.Apply` rejects a nonzero mark on Darwin, so setting it
// unconditionally made every probe fail on macOS — the platform where portal
// detection matters most, since that is where the private-address behaviour
// lives. This mirrors `client.OpenCarriers`: the mark when the platform has
// policy routing, an interface binding otherwise.
//
// iface is the attachment's own resolved name, and it is "" only where the mark
// already keeps the probe on the physical link (see attachments). It never
// borrows another attachment's name: probing the default link out of the first
// explicit bind would give the default link that bind's verdict.
func probeSocketOptions(fullTunnel bool, mark uint32, iface string) sockopt.Options {
	var opts sockopt.Options
	if fullTunnel && tun.PolicyRouting {
		opts.Mark = mark
	}
	// Bound to the link either way: without policy routing, an unbound probe
	// would follow the default route into the tunnel it is meant to test
	// (§4.1).
	opts.Device = iface
	return opts
}

// disableSystemFallback tells every detector's resolver that the system
// resolver now answers through ARC. The client calls it as soon as full-tunnel
// routing is installed; from then on a link without an upstream of its own
// reports no answer rather than measuring the tunnel (§4.4).
func disableSystemFallback(detectors map[string]*portal.Detector) {
	for _, d := range detectors {
		if r, ok := d.Prober.Rounds.(*portal.UpstreamResolver); ok {
			r.DisableSystemFallback()
		}
	}
}

// runPortalWatch keeps checking every attachment for the life of the tunnel
// (§5's steady cadence), so a lapsed grant is reported as a portal rather than
// looking like a dead relay, and a fresh login is noticed without a restart.
//
// It watches the excluded attachments too, and that is the point of taking two
// lists. Carriers are opened once, before this runs, so an attachment that was
// captive at startup has no path into the session however healthy it becomes —
// but staying silent about it is worse than the limitation: the user behind a
// hotel portal needs its URL, and the user whose Wi-Fi came back needs to know
// that a restart, not patience, is what admits it.
//
// It is deliberately a reporter. §7.1: a portal is on-path, so its verdict
// cannot lower protection — it never releases the tunnel, closes carriers, or
// changes routes. The remedy stays the user's decision, and this release does
// not implement §7.1's release command: `arc-client portal login` and
// -portal-release-tunnel are not in this tree, so what a lapse produces here is
// the warning and the URL, nothing more.
//
// It returns when ctx does, which is when the tunnel is closing anyway.
func runPortalWatch(ctx context.Context, log *slog.Logger, detectors map[string]*portal.Detector, eligible, blocked []string, cfg portal.Config) {
	login := cfg.Login
	if login <= 0 {
		login = 10 * time.Second
	}
	open := make(map[string]bool, len(eligible))
	for _, iface := range eligible {
		open[iface] = true
	}

	var wg sync.WaitGroup
	// Deterministic order keeps the journal readable when two attachments
	// transition in the same round.
	for _, iface := range append(append([]string(nil), eligible...), blocked...) {
		d := detectors[iface]
		if d == nil {
			continue
		}
		// §5: an admitted attachment is watched on the steady cadence — its
		// carriers are open, so what is left to look for is a grant lapsing or
		// being reinstated. With -portal-keepalive 0 there is no steady cadence
		// and nothing to watch it for, so it gets no watcher at all.
		//
		// An excluded attachment is watched on the login cadence whatever
		// -portal-keepalive says: zero disables the expiry check on links
		// carrying traffic, not the account of a link the user did not get.
		steady := cfg.Steady
		if !open[iface] {
			steady = login
		} else if steady <= 0 {
			continue
		}
		// The gate has just checked every attachment, so each watcher's first
		// check waits one of its own cadences. Detector.Run checks immediately
		// (which is right at startup); without this the client would probe
		// twice in the same instant. Per attachment, because an excluded link
		// is on the faster login cadence and must not inherit the steady one.
		first := steady
		if d.BlocksCarriers() {
			first = login
		}
		w := newPortalWatcher(log, iface, d, open[iface])
		d.OnChange, d.OnURL = w.onChange, w.onURL
		wg.Add(1)
		go func(d *portal.Detector, steady, first time.Duration) {
			defer wg.Done()
			select {
			case <-ctx.Done():
				return
			case <-time.After(first):
			}
			// -portal-poll is passed through, not left to Run's default: a
			// client configured for a slower login poll must behave the same
			// mid-session as at the gate, and §5 gives one loop two roles.
			d.Run(ctx, steady, login)
		}(d, steady, first)
	}
	wg.Wait()
}

// portalWatcher reports transitions during a run. Only a change is news: the
// periodic "still fine" checks must stay quiet or the journal becomes noise.
//
// Seeded with the state detection already reached, because OnChange only fires
// on a change and the seeding is what makes the first real transition legible.
//
// admitted says whether this attachment's carriers are open. An excluded one is
// watched all the same, and its recovery is reported as what it is: the network
// is usable again, but this session is not using it, because carriers are opened
// once and there is no re-open path.
//
// On expiry it prints the URL, because §7.1 makes the remedy a user action: the
// tunnel stays up, so a browser cannot reach the portal through ARC's routes
// until the user does something about it. Printing the link is the most this
// layer can usefully do, and the journal keeps the host only (§4.7).
//
// The URL is reported on its own too. A portal can hand out a new login link —
// a fresh session token, another host — without the state changing, and the
// link printed at startup is then the wrong one.
type portalWatcher struct {
	log      *slog.Logger
	iface    string
	d        *portal.Detector
	admitted bool
	last     portal.State
	shown    string // the login URL the user was last given
}

func newPortalWatcher(log *slog.Logger, iface string, d *portal.Detector, admitted bool) *portalWatcher {
	w := &portalWatcher{log: log, iface: label(iface), d: d, admitted: admitted, last: d.State()}
	if w.last.BlocksCarriers() {
		// Startup has already printed this attachment's URL (printPortalMessage
		// or announceExcluded); repeating it would be noise.
		w.shown = d.PortalURL()
	}
	return w
}

func (w *portalWatcher) onChange(state portal.State, _ portal.Check) {
	prev := w.last
	w.last = state
	if prev == state {
		return
	}
	if state.BlocksCarriers() {
		// §7.1: not a routing change. A portal is an on-path adversary that can
		// forge exactly the evidence that produced this state, so the network
		// does not get to move the user's traffic out of ARC.
		w.log.Warn("network now requires a login; the tunnel stays up", "interface", w.iface, "was", prev.String())
		url := w.d.PortalURL()
		w.shown = url
		switch {
		case !w.admitted && url != "":
			fmt.Fprintf(os.Stderr, "arc-client: %s requires a login at %s\n", w.iface, url)
		case !w.admitted:
			fmt.Fprintf(os.Stderr, "arc-client: %s requires a login ARC cannot locate\n", w.iface)
		case url != "":
			fmt.Fprintf(os.Stderr, "arc-client: %s expired; log in at %s\n", w.iface, url)
		default:
			fmt.Fprintf(os.Stderr, "arc-client: %s requires a login ARC cannot locate\n", w.iface)
		}
		return
	}
	w.shown = ""
	if !state.Usable() {
		// §6.3: inconclusive is not recovery. Saying "portal check passed" here
		// would tell the user their login worked when nothing was proven — the
		// same conflation the startup wait avoids.
		w.log.Warn("portal state inconclusive; the tunnel stays up", "interface", w.iface, "was", prev.String())
		return
	}
	if !w.admitted {
		// Excluded at startup and healthy now. There is no carrier to admit it
		// to — carriers are opened once, before the watch runs — so say that
		// plainly instead of implying the path is in use.
		w.log.Info("excluded attachment is usable again, but this session is not carrying traffic on it",
			"interface", w.iface, "was", prev.String(), "state", state.String())
		fmt.Fprintf(os.Stderr, "arc-client: %s is usable again; restart arc-client to carry traffic on it\n", w.iface)
		return
	}
	// Recovery toward none/authenticated. Logged at info because it is the
	// answer to the warning above.
	w.log.Info("portal check passed", "interface", w.iface, "was", prev.String(), "state", state.String())
}

// onURL reports a login URL that changed while the attachment is still behind
// the portal. A cleared URL is not news — the state change that cleared it, if
// any, has already spoken — and neither is the URL the user already has.
func (w *portalWatcher) onURL(url string) {
	if url == "" || url == w.shown || !w.last.BlocksCarriers() {
		return
	}
	w.shown = url
	w.log.Info("portal login page changed", "interface", w.iface, "portal_host", w.d.Host())
	fmt.Fprintf(os.Stderr, "arc-client: %s requires a login at %s\n", w.iface, url)
}

// announceExcluded tells the user about attachments left out of a session that
// is starting anyway. The journal line that lists them is for an operator; the
// user needs each one's login URL, because without it the network they meant
// to use has asked them for something they cannot see.
func announceExcluded(detectors map[string]*portal.Detector, excluded []string) {
	for _, iface := range excluded {
		d := detectors[iface]
		if d == nil {
			continue
		}
		if url := d.PortalURL(); url != "" {
			fmt.Fprintf(os.Stderr, "arc-client: %s requires a login at %s; connecting without it\n", label(iface), url)
		} else {
			fmt.Fprintf(os.Stderr, "arc-client: %s requires a login ARC cannot locate; connecting without it\n", label(iface))
		}
	}
	if len(excluded) > 0 {
		fmt.Fprintf(os.Stderr, "            restart arc-client after logging in to carry traffic on it\n")
	}
}

// portalWaitMessage is what the client does when every attachment is captive:
// it prints the login URLs and waits, re-checking on the poll cadence, so the
// user does not have to rerun the command after logging in.
//
// It returns the attachments that are no longer blocked, which is each
// attachment that recovered on its own — a captive Wi-Fi link must not hold out
// a cellular one that recovered first. A non-zero -portal-wait bounds the wait,
// so a script cannot hang behind a portal forever; a zero wait means "wait
// indefinitely", which is right for an interactive user.
//
// The polling itself is Detector.Wait, so this loop and the mid-session watch
// cannot disagree about cadence, backoff, or what counts as a pass. Both follow
// §6.3: a completed verdict that does not block carriers ends the wait, and an
// inconclusive one says so rather than being presented as a login. What a
// cancelled round can never do is end it — a deadline must not decide the
// verdict.
func portalWaitMessage(ctx context.Context, detectors map[string]*portal.Detector, blocked []string, cfg portal.Config, log *slog.Logger) ([]string, error) {
	printPortalMessage(detectors, blocked)

	// The caller's context is kept apart from the wait's. Ctrl-C ends the
	// process: it never authorizes startup, gets no grace period, and is
	// reported as itself rather than as "log in, then rerun". Only the
	// -portal-wait deadline gets the grace below, because only there can a
	// login that landed at the same instant be a real pass.
	parent := ctx
	bounded := cfg.Wait > 0
	if bounded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Wait)
		defer cancel()
	}
	// Cancelling the wait's own context is how the first recovery stops the
	// other attachments' polling; it must not cancel the caller's.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		iface string
		obs   portal.Observation
	}
	results := make(chan result, len(blocked))
	remaining := 0
	for _, iface := range blocked {
		d := detectors[iface]
		if d == nil {
			continue
		}
		remaining++
		go func(iface string, d *portal.Detector) {
			results <- result{iface: iface, obs: d.Wait(ctx, cfg.Login)}
		}(iface, d)
	}
	if remaining == 0 {
		return nil, errPortalBlocked(detectors, blocked)
	}
	var (
		passed  []string
		unclear []string
	)
	succeed := func() ([]string, error) {
		// A result that arrived together with Ctrl-C is not a reason to start.
		if err := parent.Err(); err != nil {
			return nil, err
		}
		reportRecovered(log, passed, unclear)
		return append(passed, unclear...), nil
	}

	accept := func(r result) {
		// Only a completed round counts. A Wait cancelled by the deadline
		// returns the state it had, and applying that as a verdict is how a
		// timeout becomes a login — which is the bug this whole path exists to
		// avoid.
		if !r.obs.Completed {
			return
		}
		switch {
		case r.obs.State.Usable():
			passed = append(passed, r.iface)
		case !r.obs.State.BlocksCarriers():
			// §6.3: unknown proceeds with a warning. It is not a login, so it
			// is reported separately rather than sold as one.
			unclear = append(unclear, r.iface)
		}
	}
	for {
		select {
		case <-ctx.Done():
			if err := parent.Err(); err != nil {
				return nil, err
			}
			// A recovery may have landed at the same instant the deadline did,
			// and select picks between ready cases at random. A cancelled Wait
			// returns promptly — its round is cancelled with it — so give the
			// outstanding goroutines a moment to report before deciding nothing
			// was proven. Without this, a login that completed exactly at the
			// deadline is reported as a failure.
			grace := time.NewTimer(probeGrace)
			for i := 0; i < remaining; i++ {
				select {
				case r := <-results:
					accept(r)
				case <-grace.C:
					i = remaining // stop waiting: a stuck probe must not delay exit
				}
			}
			grace.Stop()
			if len(passed)+len(unclear) > 0 {
				return succeed()
			}
			// The deadline with nothing recovered: this is the portal-blocked
			// exit, not a login.
			if bounded && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				fmt.Fprintf(os.Stderr, "arc-client: giving up after %s\n", cfg.Wait)
			}
			return nil, errPortalBlocked(detectors, blocked)
		case r := <-results:
			remaining--
			accept(r)
		}
		if len(passed)+len(unclear) > 0 {
			return succeed()
		}
		if remaining == 0 {
			if err := parent.Err(); err != nil {
				return nil, err
			}
			return nil, errPortalBlocked(detectors, blocked)
		}
	}
}

// reportRecovered says what actually happened, which §6.3 requires be
// distinguishable: a confirmed login and an inconclusive verdict both let the
// client proceed, but only one of them means the user logged in.
func reportRecovered(log *slog.Logger, passed, unclear []string) {
	if len(passed) > 0 {
		log.Info("portal passed; connecting", "interfaces", passed)
	}
	if len(unclear) > 0 {
		log.Warn("portal state inconclusive; connecting anyway, and the first carrier failure will explain itself",
			"interfaces", unclear)
		fmt.Fprintf(os.Stderr, "arc-client: %s cannot be classified; connecting anyway\n", strings.Join(unclear, ", "))
	}
}

// printPortalMessage shows each blocked attachment's login URL, or says there is
// none (§4.5).
func printPortalMessage(detectors map[string]*portal.Detector, blocked []string) {
	shown := false
	for _, iface := range blocked {
		d := detectors[iface]
		if d == nil {
			continue
		}
		if url := d.PortalURL(); url != "" {
			fmt.Fprintf(os.Stderr, "arc-client: %s requires a login at %s\n", label(iface), url)
			shown = true
		}
	}
	if shown {
		fmt.Fprintf(os.Stderr, "            log in with a browser; ARC connects as soon as it passes\n")
		return
	}
	fmt.Fprintf(os.Stderr, "arc-client: this network requires a login ARC cannot locate\n")
	fmt.Fprintf(os.Stderr, "            open a browser and it will show the portal page\n")
}

// portalBlockedError reports that detection stopped the run, so a caller can
// tell "a portal blocked us" from a real failure.
type portalBlockedError struct {
	urls []string
}

func (e *portalBlockedError) Error() string {
	if len(e.urls) > 0 {
		return fmt.Sprintf("captive portal: log in at %s, then rerun", strings.Join(e.urls, ", "))
	}
	return "captive portal: this network requires a login; open a browser to find it"
}

func errPortalBlocked(detectors map[string]*portal.Detector, blocked []string) error {
	var urls []string
	for _, iface := range blocked {
		if d := detectors[iface]; d != nil {
			if u := d.PortalURL(); u != "" {
				urls = append(urls, u)
			}
		}
	}
	return &portalBlockedError{urls: urls}
}

// isPortalBlocked reports whether err came from detection.
func isPortalBlocked(err error) bool {
	var e *portalBlockedError
	return errors.As(err, &e)
}
