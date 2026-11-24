package portal

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CheckMode is the -portal-check policy (§8).
type CheckMode uint8

const (
	// CheckAuto detects when a tunnel is being installed, which is when a
	// portal matters. It is the default because the failure it prevents is
	// silent.
	CheckAuto CheckMode = iota
	// CheckOff sends no probes. For a network that blocks the connectivity
	// endpoints, where every start would otherwise classify unknown.
	CheckOff
	// CheckForce detects even without -full-tunnel, for split-tunnel setups
	// whose carriers still meet the portal.
	CheckForce
)

// ParseCheckMode parses -portal-check.
func ParseCheckMode(s string) (CheckMode, error) {
	switch s {
	case "auto", "":
		return CheckAuto, nil
	case "off":
		return CheckOff, nil
	case "force":
		return CheckForce, nil
	}
	return CheckAuto, fmt.Errorf("portal: -portal-check must be auto, off or force, not %q", s)
}

func (m CheckMode) String() string {
	switch m {
	case CheckOff:
		return "off"
	case CheckForce:
		return "force"
	}
	return "auto"
}

// Enabled reports whether detection runs, given whether a tunnel is being
// installed.
func (m CheckMode) Enabled(tunnel bool) bool {
	switch m {
	case CheckOff:
		return false
	case CheckForce:
		return true
	}
	return tunnel
}

// Expectation is a custom probe's success criterion, from
// -portal-probe-expect STATUS[:SUBSTRING] (§8).
//
// It is required with -portal-probe, not defaulted to 204: a custom URL with a
// guessed criterion is exactly the bug §4.1 describes for the built-in
// endpoints, and guessing again would repeat it.
type Expectation struct {
	Status int
	Substr string
}

// ParseExpectation parses "204" or "200:Microsoft Connect Test". For a 3xx
// status the substring is matched against the Location header — "302:/welcome"
// — since a redirect's body says nothing.
func ParseExpectation(s string) (Expectation, error) {
	if s == "" {
		return Expectation{}, errors.New("portal: -portal-probe needs -portal-probe-expect STATUS[:SUBSTRING]")
	}
	status, substr, hasSub := strings.Cut(s, ":")
	n, err := strconv.Atoi(status)
	if err != nil || n < 100 || n > 599 {
		return Expectation{}, fmt.Errorf("portal: -portal-probe-expect: %q is not an HTTP status", status)
	}
	if hasSub && substr == "" {
		return Expectation{}, errors.New("portal: -portal-probe-expect: empty substring after ':'")
	}
	return Expectation{Status: n, Substr: substr}, nil
}

// Endpoint returns the custom endpoint as a probe endpoint. A substring match
// is used where the operator supplied one, because an operator-written
// expectation is the one place a fuzzy match is what they asked for; the
// built-in endpoints compare bodies exactly (§4.1).
func (e Expectation) Endpoint(rawURL string) Endpoint {
	return Endpoint{
		Name:   "custom",
		URL:    rawURL,
		Status: e.Status,
		Substr: e.Substr,
	}
}

// Config is the detection policy assembled from the command's flags.
type Config struct {
	Mode CheckMode
	// ProbeURL and Expect are set together, for -portal-probe.
	ProbeURL string
	Expect   Expectation
	// Steady and Login are the two cadences of §5. Login is clamped by Run.
	Steady time.Duration
	Login  time.Duration
	// Wait bounds how long to wait behind a portal, when non-zero.
	Wait time.Duration
}

// Validate checks the flag combinations §8 requires.
func (c Config) Validate() error {
	if c.ProbeURL != "" && c.Expect.Status == 0 {
		return errors.New("portal: -portal-probe requires -portal-probe-expect")
	}
	if c.ProbeURL == "" && c.Expect.Status != 0 {
		return errors.New("portal: -portal-probe-expect requires -portal-probe")
	}
	if c.Steady < 0 || c.Login < 0 || c.Wait < 0 {
		return errors.New("portal: durations must not be negative")
	}
	return nil
}
