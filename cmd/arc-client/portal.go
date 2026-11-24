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
// It returns the detectors keyed by interface, and the attachments a caller may
// still use. An empty result with no error means every attachment is captive.
func checkPortal(ctx context.Context, log *slog.Logger, cfg portal.Config, fullTunnel bool, binds []string, mark uint32) (map[string]*portal.Detector, []string, error) {
	if !cfg.Mode.Enabled(fullTunnel) {
		// §8: -portal-check off sends no probes, and says so, because a client
		// that starts silently behind a portal looks broken.
		if cfg.Mode == portal.CheckOff {
			log.Info("captive portal detection is off (-portal-check off)")
		}
		return nil, binds, nil
	}

	if len(binds) == 0 {
		binds = []string{""}
	}

	detectors := make(map[string]*portal.Detector, len(binds))

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
	results := make(chan outcome, len(binds))
	for _, iface := range binds {
		go func(iface string) {
			opts := probeSocketOptions(fullTunnel, binds, mark, iface)
			p := portal.NewProber(portal.Dialer(opts, 5*time.Second))
			if cfg.ProbeURL != "" {
				p.Endpoints = []portal.Endpoint{cfg.Expect.Endpoint(cfg.ProbeURL)}
			}
			// Probe B asks the physical link's own upstream (§4.4). Without a
			// discoverable one the verdict is unmeasurable, which the state
			// model already handles — so a host with no resolvectl or a
			// DoH-only network degrades to probe A alone rather than failing.
			p.Resolver = &portal.UpstreamResolver{Interface: iface, Sockopt: opts}
			var c portal.Classifier
			d := &portal.Detector{Prober: p, Classifier: &c, Logger: log}
			checkCtx, cancel := context.WithTimeout(ctx, startupCheckTimeout)
			defer cancel()
			results <- outcome{iface: iface, d: d, state: d.Check(checkCtx)}
		}(iface)
	}

	eligible := make([]string, 0, len(binds))
	var blocked []string
	for range binds {
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
		eligible = append(eligible, r.iface)
	}
	if err := ctx.Err(); err != nil {
		return detectors, nil, err
	}
	sort.Strings(blocked)
	for _, iface := range blocked {
		log.Info("attachment is behind a captive portal", "interface", label(iface))
	}
	return detectors, eligible, nil
}

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
func probeSocketOptions(fullTunnel bool, binds []string, mark uint32, iface string) sockopt.Options {
	var opts sockopt.Options
	if fullTunnel && tun.PolicyRouting {
		opts.Mark = mark
	}
	// Bound to the link either way: without policy routing, an unbound probe
	// would follow the default route into the tunnel it is meant to test
	// (§4.1).
	if iface != "" {
		opts.Device = iface
	} else if len(binds) > 0 {
		opts.Device = binds[0]
	}
	return opts
}

// runPortalWatch keeps checking each attachment for the life of the tunnel
// (§5's steady cadence), so a lapsed grant is reported as a portal rather than
// looking like a dead relay, and a fresh login is noticed without a restart.
//
// It is deliberately a reporter. §7.1: a portal is on-path, so its verdict
// cannot lower protection — it never releases the tunnel, closes carriers, or
// changes routes. The remedy stays the user's decision, and this release does
// not implement §7.1's release command: `arc-client portal login` and
// -portal-release-tunnel are not in this tree, so what a lapse produces here is
// the warning and the URL, nothing more.
//
// It returns when ctx does, which is when the tunnel is closing anyway.
func runPortalWatch(ctx context.Context, log *slog.Logger, detectors map[string]*portal.Detector, eligible []string, cfg portal.Config) {
	// The gate has just checked every attachment, so the first watch check must
	// wait a full cadence. Detector.Run checks immediately (which is right at
	// startup), and without this wait the client would probe twice in the same
	// instant — once at the gate and once as the watch begins.
	select {
	case <-ctx.Done():
		return
	case <-time.After(cfg.Steady):
	}

	var wg sync.WaitGroup
	for _, iface := range eligible {
		d := detectors[iface]
		if d == nil {
			continue
		}
		// §5: the watch runs on the steady cadence — the carriers are open, so
		// the only thing left to look for is a grant lapsing or being
		// reinstated. With -portal-keepalive 0 there is no steady cadence, so
		// this does not start at all.
		//
		// The watcher seeds itself from the detector's current state: OnChange
		// fires only on a change, and that seed is what makes the first real
		// transition legible rather than a repeat of the startup verdict.
		d.OnChange = portalWatcher(log, label(iface), d)
		wg.Add(1)
		go func() {
			defer wg.Done()
			d.Run(ctx, cfg.Steady, 0)
		}()
	}
	wg.Wait()
}

// portalWatcher reports transitions during a run. Only a change is news: the
// periodic "still fine" checks must stay quiet or the journal becomes noise.
//
// Seeded with the state detection already reached, because OnChange only fires
// on a change and the seeding is what makes the first real transition legible.
//
// On expiry it prints the URL, because §7.1 makes the remedy a user action: the
// tunnel stays up, so a browser cannot reach the portal through ARC's routes
// until the user does something about it. Printing the link is the most this
// layer can usefully do, and the journal keeps the host only (§4.7).
func portalWatcher(log *slog.Logger, iface string, d *portal.Detector) func(portal.State, portal.Check) {
	last := d.State()
	return func(state portal.State, _ portal.Check) {
		prev := last
		last = state
		if prev == state {
			return
		}
		if state.BlocksCarriers() {
			// §7.1: not a routing change. A portal is an on-path adversary that
			// can forge exactly the evidence that produced this state, so the
			// network does not get to move the user's traffic out of ARC.
			log.Warn("network now requires a login; the tunnel stays up", "interface", iface, "was", prev.String())
			if url := d.PortalURL(); url != "" {
				fmt.Fprintf(os.Stderr, "arc-client: %s expired; log in at %s\n", label(iface), url)
			} else {
				fmt.Fprintf(os.Stderr, "arc-client: %s requires a login ARC cannot locate\n", label(iface))
			}
			return
		}
		// Recovery toward none/authenticated. Logged at info because it is
		// the answer to the warning above.
		log.Info("portal check passed", "interface", iface, "was", prev.String(), "state", state.String())
	}
}

// portalWaitMessage is what the client does when every attachment is captive:
// it prints the login URLs and waits, re-checking on the poll cadence, so the
// user does not have to rerun the command after logging in.
//
// It returns the attachments that became usable, which is each attachment that
// passed on its own — a captive Wi-Fi link must not hold out a cellular one that
// recovered first. A non-zero -portal-wait bounds the wait, so a script cannot
// hang behind a portal forever; a zero wait means "wait indefinitely", which is
// right for an interactive user.
//
// The polling itself is Detector.Wait, so this loop and the mid-session watch
// cannot disagree about cadence, backoff, or what counts as a pass. Only a
// confirmed pass ends a wait: StateUnknown is fail-open for carriers (§6.3), but
// it is not proof of a login, and a portal that merely stopped answering would
// otherwise open carriers into a portal.
func portalWaitMessage(ctx context.Context, detectors map[string]*portal.Detector, blocked []string, cfg portal.Config, log *slog.Logger) ([]string, error) {
	printPortalMessage(detectors, blocked)

	// A deadline from -portal-wait gets its own message; the caller's own
	// context expiring (Ctrl-C, or the parent's deadline) does not, because
	// "giving up after 0s" explains nothing.
	bounded := cfg.Wait > 0
	if bounded {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Wait)
		defer cancel()
	}
	// Cancelling the wait's own context is how the first success stops the
	// other attachments' polling; it must not cancel the caller's.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		iface string
		state portal.State
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
			results <- result{iface: iface, state: d.Wait(ctx, cfg.Login)}
		}(iface, d)
	}
	if remaining == 0 {
		return nil, errPortalBlocked(detectors, blocked)
	}

	var passed []string
	for {
		select {
		case <-ctx.Done():
			// A pass may have landed at the same instant the deadline did, and
			// select picks between ready cases at random. A cancelled Wait
			// returns promptly — its check is cancelled with it — so give the
			// outstanding goroutines a moment to report before deciding nothing
			// was proven. Without this, a login that completed exactly at the
			// deadline is reported as a failure.
			grace := time.NewTimer(probeGrace)
			for i := 0; i < remaining; i++ {
				select {
				case r := <-results:
					if r.state.Usable() {
						passed = append(passed, r.iface)
					}
				case <-grace.C:
					i = remaining // stop waiting: a stuck probe must not delay exit
				}
			}
			grace.Stop()
			if len(passed) > 0 {
				log.Info("portal passed; connecting", "interfaces", passed)
				return passed, nil
			}
			// Deadline or Ctrl-C with nothing proven: this is the
			// portal-blocked exit, not a login.
			if bounded && errors.Is(ctx.Err(), context.DeadlineExceeded) {
				fmt.Fprintf(os.Stderr, "arc-client: giving up after %s\n", cfg.Wait)
			}
			return nil, errPortalBlocked(detectors, blocked)
		case r := <-results:
			remaining--
			// A cancelled check is not evidence (§5.1), and neither is the
			// state a cancelled Run leaves behind — so only a pass counts.
			if r.state.Usable() {
				passed = append(passed, r.iface)
			}
		}
		if len(passed) > 0 {
			log.Info("portal passed; connecting", "interfaces", passed)
			return passed, nil
		}
		if remaining == 0 {
			return nil, errPortalBlocked(detectors, blocked)
		}
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
