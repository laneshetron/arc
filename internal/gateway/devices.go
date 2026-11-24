package gateway

import (
	"errors"
	"net/netip"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// Devices managing devices (self-service-accounts.md §3.8).

// ListDevices answers a session's DEVICES_REQUEST, as
// session.RelayConfig.Devices: the session's account's devices, from the
// last applied state. While the relay is not serving, the request is
// left unanswered (false).
func (g *Gateway) ListDevices(s *session.RelaySession, req wire.DevicesRequest) (wire.Devices, bool) {
	return g.listDevices(netip.AddrFrom4(s.Config().IPv4), s)
}

func (g *Gateway) listDevices(addr netip.Addr, s *session.RelaySession) (wire.Devices, bool) {
	g.mu.Lock()
	defer g.mu.Unlock()
	d, ok := g.managerLocked(addr, s)
	if !ok {
		return wire.Devices{Status: wire.CodeUnauthorized}, true
	}
	if g.cfg.Gate != nil && !g.cfg.Gate() {
		return wire.Devices{}, false
	}
	now := g.now()
	var out wire.Devices
	for _, x := range g.st.DevicesOf(d.Account) {
		info := wire.DeviceInfo{ID: x.ID, Created: unix(x.Created), LastSeen: unix(g.lastSeenLocked(x.ID, now)), Name: x.Name}
		if n := len(x.Lineage); n > 0 {
			info.Parent = x.Lineage[n-1]
		}
		copy(info.Key[:], x.Key)
		out.Devices = append(out.Devices, info)
	}
	return out, true
}

// RevokeDevice answers a session's REVOKE_REQUEST, as
// session.RelayConfig.Revoke: the revocation is committed apart from the
// caller, and answered (status 0) once the relay has applied it; a
// device already revoked is answered at once. Until then, and while the
// relay is not serving, the request is left unanswered (false), and the
// client's repeat of it gets the answer. A device that revokes itself
// is closed with REVOKED instead.
func (g *Gateway) RevokeDevice(s *session.RelaySession, req wire.RevokeRequest) (wire.RevokeResult, bool) {
	return g.revokeDevice(netip.AddrFrom4(s.Config().IPv4), s, req)
}

func (g *Gateway) revokeDevice(addr netip.Addr, s *session.RelaySession, req wire.RevokeRequest) (wire.RevokeResult, bool) {
	refuse := wire.RevokeResult{Status: wire.CodeUnauthorized}
	g.mu.Lock()
	defer g.mu.Unlock()
	d, ok := g.managerLocked(addr, s)
	if !ok {
		// A device that revoked itself has no lease to identify it with any
		// more, so managerLocked fails for its own request's repeat. The
		// repeat is the normal retry path — the client repeats until
		// answered — and answering it UNAUTHORIZED would report a completed
		// revocation as a refusal. Its own tombstone is the record that the
		// request was done, so ask that instead of the lease.
		if a, done := g.repeatOfSelfRevokeLocked(addr, s, req); done {
			return a, true
		}
		return refuse, true
	}
	if g.cfg.Gate != nil && !g.cfg.Gate() {
		return wire.RevokeResult{}, false
	}
	now := g.now()
	g.sweepMinting(now)
	request, target := accounts.ID(req.RequestID), accounts.ID(req.DeviceID)
	if p := g.revoking[d.ID]; p != nil {
		if !p.done {
			return wire.RevokeResult{}, false
		}
		delete(g.revoking, d.ID)
		if p.request == request && p.err != nil && revokeRefused(p.err) {
			return refuse, true
		}
	}
	// The applied state decides: a refusal, or nothing left to revoke
	// (such as a request already done, which its tombstones record, even
	// past a restore), is answered at once; anything else is committed.
	gone, err := accounts.RevokeByDevice(g.st.Clone(), d.ID, request, target, req.Descendants, now)
	switch {
	case err != nil && revokeRefused(err):
		return refuse, true
	case err != nil:
		return wire.RevokeResult{}, false
	case len(gone) == 0:
		return wire.RevokeResult{}, true
	case g.committing >= maxMinting:
		return wire.RevokeResult{}, false
	}
	// Apply, given the committed state, logs it and closes the revoked
	// devices' sessions.
	g.startCommitLocked(g.revoking, d.ID, request, now, func(st *accounts.State) error {
		gone, err := accounts.RevokeByDevice(st, d.ID, request, target, req.Descendants, now)
		if err == nil && len(gone) == 0 {
			return errNoChange
		}
		return err
	})
	return wire.RevokeResult{}, false
}

// revokeRefused reports whether a revocation error is final for the
// request (the client is told UNAUTHORIZED), rather than one to retry.
func revokeRefused(err error) bool {
	return errors.Is(err, accounts.ErrNoManage) || errors.Is(err, accounts.ErrCoolingOff) || errors.Is(err, accounts.ErrNoDevice)
}

// repeatOfSelfRevokeLocked answers a repeat of a request whose device has
// already revoked itself, and reports whether the request was that one.
//
// A self-revoke revokes its own device, so by the time the repeat arrives
// the lease it would be identified by is marked revoked and managerLocked
// refuses it. The tombstone that revocation left is the record: it names
// the revoker and the request, so a repeat with the same request ID is
// answered as done rather than as unauthorized.
//
// Only the device's own self-revocation is matched. A device revoked by
// another must not be able to use that as a standing authorization to
// submit further requests, which is why the check is that the tombstone's
// revoker is the device itself.
func (g *Gateway) repeatOfSelfRevokeLocked(addr netip.Addr, s *session.RelaySession, req wire.RevokeRequest) (wire.RevokeResult, bool) {
	if g.st == nil {
		return wire.RevokeResult{}, false
	}
	l, ok := g.leased[addr]
	// The lease must still be the one this session held, or a new session
	// could claim a finished request by guessing its ID.
	if !ok || l.session != s || !l.revoked {
		return wire.RevokeResult{}, false
	}
	request, device := accounts.ID(req.RequestID), accounts.ID(req.DeviceID)
	for _, t := range g.st.Revoked {
		if t.By != l.device || t.ID != device || t.Request != request {
			continue
		}
		return wire.RevokeResult{Status: 0}, true
	}
	return wire.RevokeResult{}, false
}

// managerLocked returns the device of the session leasing addr, if it
// may manage its account's devices.
func (g *Gateway) managerLocked(addr netip.Addr, s *session.RelaySession) (*accounts.Device, bool) {
	l, ok := g.leased[addr]
	if !ok || l.session != s || l.revoked || g.st == nil || g.cfg.Commit == nil {
		return nil, false
	}
	d := g.st.DeviceByID(l.device)
	if d == nil || !g.st.MayManage(d) {
		return nil, false
	}
	return d, true
}

// lastSeenLocked is when device last had a session: now if it has one,
// else when its last one here ended, or zero if none has since the relay
// started.
func (g *Gateway) lastSeenLocked(device accounts.ID, now time.Time) time.Time {
	for _, l := range g.leased {
		if l.device == device && l.session != nil && !l.revoked {
			return now
		}
	}
	return g.seen[device]
}

func unix(t time.Time) uint32 {
	if t.IsZero() || t.Unix() < 0 {
		return 0
	}
	return uint32(t.Unix())
}

// logRevokedLocked warns of each revocation by a device that st has and
// the last applied state lacks, naming the account, the revoking device
// and the revoked one, so the operator sees it unprompted (§3.8).
func (g *Gateway) logRevokedLocked(st *accounts.State) {
	if g.st == nil || g.cfg.Log == nil {
		return
	}
	type key struct {
		id, by, request accounts.ID
		until           int64
	}
	known := map[key]bool{}
	for _, t := range g.st.Revoked {
		known[key{t.ID, t.By, t.Request, t.Until.Unix()}] = true
	}
	for _, t := range st.Revoked {
		if t.By.IsZero() || !t.Restored.IsZero() || known[key{t.ID, t.By, t.Request, t.Until.Unix()}] {
			continue
		}
		account, by, revoked := "", t.By.String(), t.ID.String()
		if d := g.st.DeviceByID(t.ID); d != nil {
			revoked = d.Name
			if a := g.st.AccountByID(d.Account); a != nil {
				account = a.Name
			}
		}
		if d := st.DeviceByID(t.By); d != nil {
			by = d.Name
		} else if d := g.st.DeviceByID(t.By); d != nil {
			by = d.Name
		}
		g.cfg.Log.Warn("device revoked by a device", "account", account, "by", by, "device", revoked,
			"restore_until", t.Until)
	}
}
