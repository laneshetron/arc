package client

import (
	"errors"

	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

var errMode = errors.New("want off, auto, or always")

// ParseRedundancy reads a redundancy policy: off, auto or always.
func ParseRedundancy(s string) (session.RedundancyPolicy, error) {
	switch s {
	case "off":
		return session.RedundancyOff, nil
	case "auto":
		return session.RedundancyAuto, nil
	case "always":
		return session.RedundancyAlways, nil
	}
	return 0, errMode
}

// ParseFEC reads a forward error correction mode: off, auto or always.
func ParseFEC(s string) (wire.FECMode, error) {
	switch s {
	case "off":
		return wire.FECOff, nil
	case "auto":
		return wire.FECAuto, nil
	case "always":
		return wire.FECAlways, nil
	}
	return 0, errMode
}

// ParseSplitTCP reads a split TCP mode: off, auto or always.
func ParseSplitTCP(s string) (engine.SplitMode, error) {
	switch s {
	case "off":
		return engine.SplitOff, nil
	case "auto":
		return engine.SplitAuto, nil
	case "always":
		return engine.SplitAlways, nil
	}
	return 0, errMode
}
