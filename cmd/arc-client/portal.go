package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/laneshetron/arc/internal/carrier/sockopt"
	"github.com/laneshetron/arc/internal/portal"
)

// portalState is the subset of the portal classifier's state the client needs
// at startup, kept separate so the rest of run() does not import the package's
// full surface.
type portalState = portal.State

// checkPortal runs one round of captive-portal detection and returns the
// detector so the caller can wait on it, along with the state and the URL.
//
// It never fails the run. Detection is a courtesy to the user and a guard on
// carrier attempts; a network that blocks the probes is classified unknown and
// the client proceeds, which is what spec/captive-portals.md §6.3 requires.
func checkPortal(log *slog.Logger, cfg portal.Config, fullTunnel bool, binds []string, mark uint32, noOffload bool) (*portal.Detector, error) {
	if !cfg.Mode.Enabled(fullTunnel) {
		// §8: -portal-check off sends no probes, and says so, because a client
		// that starts silently behind a portal looks broken.
		if cfg.Mode == portal.CheckOff {
			log.Info("captive portal detection is off (-portal-check off)")
		}
		return nil, nil
	}

	// The probe socket must bypass the TUN (§4.1). Before the tunnel exists
	// there is nothing to bypass, so only the mark matters, and only once
	// full-tunnel routing is installed — which it is not yet.
	var opts sockopt.Options
	if !noOffload {
		opts.Mark = mark
	}
	if len(binds) > 0 {
		opts.Device = binds[0]
	}

	p := portal.NewProber(portal.Dialer(opts, 5*time.Second))
	if cfg.ProbeURL != "" {
		p.Endpoints = []portal.Endpoint{cfg.Expect.Endpoint(cfg.ProbeURL)}
	}

	var c portal.Classifier
	return &portal.Detector{Prober: p, Classifier: &c, Logger: log}, nil
}

// portalWaitMessage is what the client does when a portal blocks it: it prints
// the login URL and then waits for the login, re-checking on the poll cadence,
// so the user does not have to rerun the command after logging in.
//
// A non-zero -portal-wait bounds the wait, so a script cannot hang behind a
// portal forever. A zero wait means "wait indefinitely", which is right for an
// interactive user watching the message.
func portalWaitMessage(ctx context.Context, d *portal.Detector, cfg portal.Config, log *slog.Logger) error {
	_, url := d.Blocked()
	printPortalMessage(url)

	if cfg.Wait > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Wait)
		defer cancel()
	}

	login := cfg.Login
	if login <= 0 {
		login = 10 * time.Second
	}

	// Poll on the login cadence until the state stops blocking or the wait
	// expires. This is the same loop Detector.Run would drive, but here it
	// gates the run rather than running alongside it.
	t := time.NewTicker(login)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			if errors.Is(ctx.Err(), context.DeadlineExceeded) {
				fmt.Fprintf(os.Stderr, "arc-client: giving up after %s\n", cfg.Wait)
			}
			return errPortalBlocked(url, d.State())
		case <-t.C:
		}
		if state := d.Check(ctx); !state.BlocksCarriers() {
			log.Info("portal passed; connecting", "state", state.String())
			return nil
		}
	}
}

// printPortalMessage shows the login URL, or says there is none (§4.5).
func printPortalMessage(url string) {
	if url != "" {
		fmt.Fprintf(os.Stderr, "arc-client: this network requires a login at https://%s\n", url)
		fmt.Fprintf(os.Stderr, "            log in with a browser; ARC connects as soon as it passes\n")
		return
	}
	fmt.Fprintf(os.Stderr, "arc-client: this network requires a login ARC cannot locate\n")
	fmt.Fprintf(os.Stderr, "            open a browser and it will show the portal page\n")
}

// errPortalBlocked is returned when detection stops the run. It is a distinct
// error so a caller (or a test) can tell "a portal blocked us" from a real
// failure, and it carries the URL so a script can surface it.
type portalBlockedError struct {
	url   string
	state portalState
}

func (e *portalBlockedError) Error() string {
	if e.url != "" {
		return fmt.Sprintf("captive portal: log in at https://%s, then rerun", e.url)
	}
	return "captive portal: this network requires a login; open a browser to find it"
}

func errPortalBlocked(url string, state portalState) error {
	return &portalBlockedError{url: url, state: state}
}

// isPortalBlocked reports whether err came from detection.
func isPortalBlocked(err error) bool {
	var e *portalBlockedError
	return errors.As(err, &e)
}
