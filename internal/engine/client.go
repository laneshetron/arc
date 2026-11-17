package engine

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/laneshetron/arc/internal/bufpool"
	"github.com/laneshetron/arc/internal/diag"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/splittcp"
	"github.com/laneshetron/arc/internal/wire"
)

// Carrier is one underlay the client can reach the relay through, such as
// a socket bound to one network interface.
type Carrier struct {
	Name string // for logs, e.g. the interface name
	Conn DatagramConn
	// Relay is the relay address this carrier sends to and accepts
	// packets from; zero means ClientConfig.Relay. A stream carrier sends
	// to its own endpoint and reports packets as coming from Relay.
	Relay netip.AddrPort
	// Fallback marks the carrier's path for use only while no other path
	// is healthy, as for TLS/TCP (spec §16.3).
	Fallback bool
}

// A Request is an exchange of requests the relay answers, each sent
// reliably and repeated until answered, since the relay may hold one it
// cannot answer yet.
type Request struct {
	// Send sends the exchange's current request, once each session is
	// active, then every Repeat until Answer ends the exchange. An error
	// (such as session.ErrNoInvites, from a relay that offers the device
	// none) closes the session, and RunClient returns it.
	Send func(*session.Client) error
	// Answer is given each answer the relay sends: an InviteAnswer,
	// DevicesAnswer or RevokeAnswer, which may answer an earlier request.
	// more says the exchange goes on, and its next request is sent at
	// once; an error closes the session, and RunClient returns it.
	Answer func(session.ClientEvent) (more bool, err error)
	Repeat time.Duration // default 2 s
}

// InviteRequest is a Request for an invite with request ID id, whose
// answer goes to answer (§3.6).
func InviteRequest(id [8]byte, answer func(session.InviteAnswer) error) *Request {
	return &Request{
		Send: func(c *session.Client) error { return c.RequestInvite(id) },
		Answer: func(e session.ClientEvent) (bool, error) {
			if a, ok := e.(session.InviteAnswer); ok && a.RequestID == id {
				return false, answer(a)
			}
			return true, nil
		},
	}
}

// ClientConfig configures a client engine.
type ClientConfig struct {
	Session  session.ClientConfig
	Relay    netip.AddrPort
	Carriers []Carrier // at least one
	TUN      PacketDevice

	// OnEstablished configures the local network (address, MTU, routes)
	// each time a session becomes active. A reconnect may lease a
	// different address.
	OnEstablished func(wire.AuthResult) error
	// OnEnrolled, if set, is called with the relay's ENROLLED, after
	// OnEstablished, for a session that enrolled with an invite. An
	// error closes the session and RunClient returns it.
	OnEnrolled func(session.Enrolled) error
	// Request, if set, runs a request-and-answer exchange with the relay
	// on each active session: asking for an invite, the device list, or
	// a revocation (self-service-accounts.md §3.6, §3.8).
	Request *Request

	// ReconnectDelay is the pause before replacing a session that ended
	// for a reason other than authentication failure. Default 1 s.
	ReconnectDelay time.Duration
	// RejoinDelay is the pause before a carrier whose path closed tries to
	// join the session again. Default 5 s.
	RejoinDelay time.Duration
	Logger      *slog.Logger

	// StatusInterval, if nonzero, logs each path's state that often.
	StatusInterval time.Duration

	// SplitTCP selects the new TCP connections the client terminates
	// locally and carries as streams (spec §11.3), if the relay supports
	// them.
	SplitTCP SplitMode

	// Diagnostics, if set, is uploaded to the relay's operator (spec
	// §11.4) when the relay accepts diagnostics: DiagnosticsDelay after
	// each session is established (default 5 s), then every
	// DiagnosticsInterval (default 10 min). Every DiagnosticsInterval the
	// paths' state is also logged at debug level, for the journal.
	Diagnostics         *diag.Journal
	DiagnosticsDelay    time.Duration
	DiagnosticsInterval time.Duration
}

// SplitMode selects which TCP connections become streams.
type SplitMode uint8

const (
	SplitOff SplitMode = iota
	// SplitAuto splits connections opened while the primary path loses
	// at least SplitAutoLoss of its packets in either direction.
	SplitAuto
	SplitAlways
)

func (m SplitMode) String() string {
	switch m {
	case SplitOff:
		return "off"
	case SplitAuto:
		return "auto"
	case SplitAlways:
		return "always"
	}
	return fmt.Sprintf("SplitMode(%d)", uint8(m))
}

// SplitAutoLoss is the loss rate at which SplitAuto splits new
// connections.
const SplitAutoLoss = 0.1

// splitFlow is a TCP connection sent to the userspace stack: its packets
// keep going there for as long as it lives.
type splitFlow struct {
	bridge *bridge
	last   time.Time // last packet from the application
}

// splitIdle is how long a split flow whose connection is gone keeps
// steering its packets to the stack, which answers late ones.
const splitIdle = 2 * time.Minute

// carrierState records which session path, if any, a carrier carries.
type carrierState struct {
	Carrier
	bound   bool
	path    uint32
	retryAt time.Time // when an unbound carrier may next try to join

	out    [][]byte         // reused per flush: datagrams for this carrier
	to     []netip.AddrPort // and their destinations
	elicit []bool           // and whether the relay owes each a reply

	warnAt    time.Time // when the next send failure may be logged
	sendFails int       // send failures since the last one logged
}

// sendWarnInterval is the least time between a carrier's "send failed"
// warnings. A carrier whose sends keep failing (the network down, or its
// address gone) fails on every flush, many times a millisecond under load.
const sendWarnInterval = 2 * time.Second

// sendFailed logs a failed send, unless one was logged in the last
// sendWarnInterval; the next warning counts the failures in between.
func (cs *carrierState) sendFailed(log *slog.Logger, now time.Time, err error) {
	cs.sendFails++
	if now.Before(cs.warnAt) {
		return
	}
	log.Warn("send failed", "carrier", cs.Name, "err", err, "failures", cs.sendFails)
	cs.warnAt, cs.sendFails = now.Add(sendWarnInterval), 0
}

// slotRetry is how soon to retry joining when the relay has not issued a
// path slot yet.
const slotRetry = 200 * time.Millisecond

// RunClient runs sessions until ctx is canceled, authentication fails, or
// an I/O error occurs. It reconnects after resets and timeouts.
//
// Each handshake goes out on every carrier at once, and the carrier the
// relay's response arrives on becomes path 0: on links that lose most
// packets, more attempts per second is what gets a session up, and a dead
// link cannot block one. Once the session is active, each other carrier
// joins as another path, and a carrier whose path closes rejoins after
// RejoinDelay.
//
// The caller owns the carriers' connections and the TUN and must close
// them after RunClient returns, which also stops the reader goroutines.
func RunClient(ctx context.Context, cfg ClientConfig) error {
	if len(cfg.Carriers) == 0 {
		return errors.New("engine: no carriers")
	}
	if cfg.ReconnectDelay == 0 {
		cfg.ReconnectDelay = time.Second
	}
	if cfg.RejoinDelay == 0 {
		cfg.RejoinDelay = 5 * time.Second
	}
	if cfg.DiagnosticsDelay == 0 {
		cfg.DiagnosticsDelay = 5 * time.Second
	}
	if cfg.DiagnosticsInterval == 0 {
		cfg.DiagnosticsInterval = 10 * time.Minute
	}
	log := cfg.Logger
	if log == nil {
		log = slog.Default()
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	udpCh, tunCh := make(chan datagrams, 16), make(chan [][]byte, 16)
	errc := make(chan error, len(cfg.Carriers)+1)
	carriers := make([]*carrierState, len(cfg.Carriers))
	for i, cr := range cfg.Carriers {
		if !cr.Relay.IsValid() {
			cr.Relay = cfg.Relay
		}
		carriers[i] = &carrierState{Carrier: cr}
		go readDatagrams(ctx, i, cr.Conn, udpCh, errc)
	}
	go readPackets(ctx, cfg.TUN, tunCh, errc)

	// hs tracks where handshake packets go: every carrier, or only the one
	// a COOKIE_REPLY arrived on, since the cookie is valid only for that
	// carrier's address (§9.3).
	hs := handshakeState{pinned: -1}
	newSession := func(now time.Time) (*session.Client, error) {
		log.Info("connecting", "relay", cfg.Relay, "carriers", len(carriers))
		return session.NewClient(cfg.Session, now)
	}

	c, err := newSession(time.Now())
	if err != nil {
		return err
	}
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()
	var status <-chan time.Time
	if cfg.StatusInterval > 0 {
		t := time.NewTicker(cfg.StatusInterval)
		defer t.Stop()
		status = t.C
	}
	var reconnectAt time.Time
	var toTUN [][]byte
	var requestAt time.Time // the next repeat of cfg.Request's request; zero for none
	requestDone := false    // cfg.Request's exchange has ended
	if cfg.Request != nil && cfg.Request.Repeat <= 0 {
		cfg.Request.Repeat = 2 * time.Second
	}
	sendRequest := func(now time.Time) error {
		requestAt = now.Add(cfg.Request.Repeat)
		if err := cfg.Request.Send(c); err != nil && !errors.Is(err, session.ErrNotActive) {
			c.Close(now)
			flushTransmits(c, carriers, hs.pinned, log)
			return err
		}
		c.Tick(now)
		return nil
	}
	// answered hands cfg.Request an answer.
	answered := func(e session.ClientEvent) error {
		if cfg.Request == nil || requestAt.IsZero() {
			return nil
		}
		more, err := cfg.Request.Answer(e)
		now := time.Now()
		switch {
		case err != nil:
			c.Close(now)
			flushTransmits(c, carriers, hs.pinned, log)
			return err
		case more:
			return sendRequest(now)
		}
		requestAt, requestDone = time.Time{}, true
		return nil
	}

	// Diagnostics: the next upload, and the one in flight.
	var uploadAt time.Time
	var upload *bridge
	var snapshots <-chan time.Time
	if cfg.Diagnostics != nil {
		t := time.NewTicker(cfg.DiagnosticsInterval)
		defer t.Stop()
		snapshots = t.C
	}

	// Split TCP: the userspace stack, created with the first session.
	var split *splittcp.Stack
	var accepts <-chan *splittcp.Conn
	splitOut := make(chan [][]byte, 16)
	flows := map[splittcp.Flow]*splitFlow{}
	bridges := map[uint32]*bridge{}
	bridgeEvents := make(chan bridgeEvent, 64)
	var sweepAt time.Time
	defer func() {
		for _, b := range bridges {
			b.finish(true)
		}
		if split != nil {
			split.Close()
		}
	}()
	wantSplit := func(now time.Time) bool {
		switch {
		case split == nil || !c.StreamsSupported():
			return false
		case cfg.SplitTCP == SplitAlways:
			return true
		}
		for _, p := range c.Paths(now) {
			if p.Primary {
				return p.Loss >= SplitAutoLoss
			}
		}
		return false
	}

	for {
		hs.update(c, carriers)
		joinCarriers(c, carriers, cfg.RejoinDelay, log)
		flushTransmits(c, carriers, hs.pinned, log)
		toTUN = toTUN[:0]
		for e, ok := c.PollEvent(); ok; e, ok = c.PollEvent() {
			switch e := e.(type) {
			case session.Established:
				addr := netip.AddrFrom4(e.Config.IPv4)
				log.Info("session established", "address", netip.PrefixFrom(addr, int(e.Config.Prefix4)), "mtu", e.Config.TunMTU,
					"carrier", pathCarrier(carriers, 0), "features", e.Config.Features)
				if cfg.Diagnostics != nil && c.DiagnosticsSupported() {
					uploadAt = time.Now().Add(cfg.DiagnosticsDelay)
				}
				if cfg.OnEstablished != nil {
					if err := cfg.OnEstablished(e.Config); err != nil {
						c.Close(time.Now())
						return err
					}
				}
				if cfg.Request != nil && !requestDone {
					if err := sendRequest(time.Now()); err != nil {
						return err
					}
				}
				if cfg.SplitTCP != SplitOff && split == nil {
					if split, err = splittcp.New(uint32(e.Config.TunMTU)); err != nil {
						return err
					}
					accepts = split.Accept()
					go func() {
						for {
							pkts, err := split.ReadOutbound(ctx, readBatch)
							if err != nil {
								return
							}
							select {
							case splitOut <- pkts:
							case <-ctx.Done():
								return
							}
						}
					}()
				}
			case session.Enrolled:
				log.Info("enrolled", "device", e.Name, "id", hex.EncodeToString(e.DeviceID[:]))
				if cfg.OnEnrolled != nil {
					if err := cfg.OnEnrolled(e); err != nil {
						c.Close(time.Now())
						flushTransmits(c, carriers, hs.pinned, log)
						return err
					}
				}
			case session.InviteAnswer, session.DevicesAnswer, session.RevokeAnswer:
				if err := answered(e); err != nil {
					return err
				}
			case session.PathValidated:
				log.Info("path validated", "path", e.ID)
			case session.RedundancyChanged:
				log.Info("redundancy changed", "uplink", e.Uplink, "downlink", e.Downlink)
			case session.PathClosed:
				log.Info("path closed", "path", e.ID, "reason", e.Err)
				for _, cs := range carriers {
					if cs.bound && cs.path == e.ID {
						cs.bound = false
						cs.retryAt = time.Now().Add(cfg.RejoinDelay)
						break
					}
				}
			case session.StreamUpdate:
				if b := bridges[e.ID]; b != nil {
					b.service(time.Now())
				}
			case session.Closed:
				for _, b := range bridges {
					b.finish(true) // the session's streams are gone
				}
				uploadAt, upload, requestAt = time.Time{}, nil, time.Time{}
				if errors.Is(e.Err, session.ErrAuthFailed) {
					return e.Err
				}
				log.Warn("session ended; reconnecting", "reason", e.Err, "after", cfg.ReconnectDelay)
				reconnectAt = time.Now().Add(cfg.ReconnectDelay)
			}
		}
		for p, ok := c.PollIP(); ok; p, ok = c.PollIP() {
			toTUN = append(toTUN, p)
		}
		if len(toTUN) > 0 {
			if err := cfg.TUN.Write(toTUN); err != nil {
				log.Warn("tun write failed", "err", err)
			}
			for _, p := range toTUN {
				bufpool.Put(p)
			}
		}

		deadline := c.NextDeadline()
		if c.State() == session.StateActive {
			for _, cs := range carriers {
				if cs.bound {
					continue
				}
				due := cs.retryAt
				if due.IsZero() { // never tried: join now
					due = time.Now()
				}
				if deadline.IsZero() || due.Before(deadline) {
					deadline = due
				}
			}
		}
		if !uploadAt.IsZero() && (deadline.IsZero() || uploadAt.Before(deadline)) {
			deadline = uploadAt
		}
		if !requestAt.IsZero() && (deadline.IsZero() || requestAt.Before(deadline)) {
			deadline = requestAt
		}
		if !reconnectAt.IsZero() {
			deadline = reconnectAt
		}
		resetTimer(timer, deadline)

		select {
		case <-ctx.Done():
			c.Close(time.Now())
			flushTransmits(c, carriers, hs.pinned, log)
			return ctx.Err()
		case err := <-errc:
			return err
		case d := <-udpCh:
			cs := carriers[d.carrier]
			now := time.Now()
			for i, p := range d.pkts {
				switch {
				case d.from[i] != cs.Relay:
				case cs.bound:
					c.HandlePacket(now, cs.path, p)
				case c.State() == session.StateHandshaking:
					hs.receive(c, now, d.carrier, carriers, p)
				}
				bufpool.Put(p) // the session keeps no reference to its input
			}
		case pkts := <-tunCh:
			now := time.Now()
			for _, p := range pkts {
				if split != nil && splitPacket(now, p, flows, wantSplit) {
					split.Inject(p)
				} else {
					c.SendIP(now, p) // dropped while not active, like an unplugged link
				}
				bufpool.Put(p) // both copied what they needed
			}
			if split != nil && now.After(sweepAt) {
				sweepAt = now.Add(splitIdle / 4)
				for f, sf := range flows {
					if (sf.bridge == nil || sf.bridge.finished) && now.Sub(sf.last) > splitIdle {
						delete(flows, f)
					}
				}
			}
		case pkts := <-splitOut:
			if err := cfg.TUN.Write(pkts); err != nil {
				log.Warn("tun write failed", "err", err)
			}
		case conn := <-accepts:
			now := time.Now()
			id, err := c.OpenStream(now, conn.Dst)
			if err != nil {
				conn.Abort()
				break
			}
			b := newBridge(id, c, conn, conn.Abort)
			bridges[id] = b
			b.forget = func() { delete(bridges, id) }
			if sf := flows[splittcp.Flow{Src: conn.Src, Dst: conn.Dst}]; sf != nil {
				sf.bridge = b
			}
			b.start(ctx, bridgeEvents)
			b.service(now)
		case e := <-bridgeEvents:
			e.b.handle(time.Now(), e)
		case <-status:
			logPaths(log, slog.LevelInfo, c, carriers, time.Now())
		case <-snapshots:
			logPaths(log, slog.LevelDebug, c, carriers, time.Now())
		case <-timer.C:
			now := time.Now()
			if !uploadAt.IsZero() && !now.Before(uploadAt) {
				uploadAt = now.Add(cfg.DiagnosticsInterval)
				if upload == nil || upload.finished {
					upload = startUpload(ctx, c, cfg.Diagnostics, bridges, bridgeEvents, log, now)
				}
			}
			if !requestAt.IsZero() && !now.Before(requestAt) && c.State() == session.StateActive {
				if err := sendRequest(now); err != nil {
					return err
				}
			}
			if !reconnectAt.IsZero() && !now.Before(reconnectAt) {
				reconnectAt = time.Time{}
				if c, err = newSession(now); err != nil {
					return err
				}
				continue
			}
			c.Tick(now)
		}
	}
}

// joinCarriers binds eligible underlays to new paths in the active session.
func joinCarriers(c *session.Client, carriers []*carrierState, rejoinDelay time.Duration, log *slog.Logger) {
	if c.State() != session.StateActive {
		return
	}
	now := time.Now()
	for _, cs := range carriers {
		if cs.bound || now.Before(cs.retryAt) {
			continue
		}
		id, err := c.OpenPath(now)
		switch {
		case err == nil:
			cs.bound, cs.path = true, id
			if cs.Fallback {
				c.SetFallback(id, true)
			}
		case errors.Is(err, session.ErrNoPathSlots):
			cs.retryAt = now.Add(slotRetry)
		default:
			cs.retryAt = now.Add(rejoinDelay)
			log.Warn("joining carrier failed", "carrier", cs.Name, "err", err)
		}
	}
}

// handshakeState steers handshake packets across carriers.
type handshakeState struct {
	client  *session.Client
	attempt uint64
	pinned  int // carrier holding the attempt's cookie, or -1 for all
	active  bool
}

// update unbinds every carrier when a handshake attempt starts, since path
// 0 will be whichever carrier the response arrives on.
func (h *handshakeState) update(c *session.Client, carriers []*carrierState) {
	handshaking := c.State() == session.StateHandshaking
	if handshaking && (!h.active || c != h.client || c.HandshakeAttempt() != h.attempt) {
		for _, cs := range carriers {
			cs.bound, cs.path, cs.retryAt = false, 0, time.Time{}
		}
		h.client, h.attempt, h.pinned = c, c.HandshakeAttempt(), -1
	}
	h.active = handshaking
}

// receive handles a packet from the relay on an unbound carrier during the
// handshake, binding that carrier to path 0 if it completes the handshake.
func (h *handshakeState) receive(c *session.Client, now time.Time, carrier int, carriers []*carrierState, p []byte) {
	if t, err := wire.PeekType(p); err == nil && t == wire.TypeCookieReply {
		h.pinned = carrier
	}
	c.HandlePacket(now, 0, p)
	if c.State() != session.StateHandshaking {
		cs := carriers[carrier]
		cs.bound, cs.path = true, 0
		if cs.Fallback {
			c.SetFallback(0, true)
		}
	}
}

// flushTransmits batches outgoing datagrams by their bound carrier. While
// handshaking, path 0's datagrams go to every carrier, or to pinned if it
// is not -1.
func flushTransmits(c *session.Client, carriers []*carrierState, pinned int, log *slog.Logger) {
	handshaking := c.State() == session.StateHandshaking
	for d, ok := c.PollTransmit(); ok; d, ok = c.PollTransmit() {
		if handshaking && d.PathID == 0 {
			for i, cs := range carriers {
				if pinned < 0 || i == pinned {
					// A copy each: the buffers are returned per carrier.
					cs.out, cs.to = append(cs.out, append(bufpool.Get(), d.Data...)), append(cs.to, cs.Relay)
					cs.elicit = append(cs.elicit, d.AckEliciting)
				}
			}
			bufpool.Put(d.Data)
			continue
		}
		sent := false
		for _, cs := range carriers {
			if cs.bound && cs.path == d.PathID {
				cs.out, cs.to = append(cs.out, d.Data), append(cs.to, cs.Relay)
				cs.elicit = append(cs.elicit, d.AckEliciting)
				sent = true
				break
			}
		}
		if !sent {
			bufpool.Put(d.Data)
		}
	}
	for _, cs := range carriers {
		if len(cs.out) == 0 {
			continue
		}
		var err error
		if ew, ok := cs.Conn.(elicitingWriter); ok {
			err = ew.WriteBatchEliciting(cs.out, cs.to, cs.elicit)
		} else {
			err = cs.Conn.WriteBatch(cs.out, cs.to)
		}
		if err != nil {
			cs.sendFailed(log, time.Now(), err)
		}
		// WriteBatch has copied or sent everything; the buffers are free.
		for i, p := range cs.out {
			bufpool.Put(p)
			cs.out[i] = nil
		}
		cs.out, cs.to, cs.elicit = cs.out[:0], cs.to[:0], cs.elicit[:0]
	}
}

// elicitingWriter is a carrier that is told which datagrams the relay
// owes a reply (session.Datagram.AckEliciting): a stream carrier watches
// for those replies to find a connection a censor silently froze.
type elicitingWriter interface {
	WriteBatchEliciting(pkts [][]byte, addrs []netip.AddrPort, eliciting []bool) error
}

// startUpload uploads what the journal holds on a diagnostics stream, if
// anything, and returns its bridge.
func startUpload(ctx context.Context, c *session.Client, j *diag.Journal, bridges map[uint32]*bridge,
	events chan bridgeEvent, log *slog.Logger, now time.Time) *bridge {
	data, commit := j.Pending()
	if len(data) == 0 {
		return nil
	}
	id, err := c.OpenDiagnostics(now)
	if err != nil {
		log.Debug("diagnostics upload", "err", err)
		return nil
	}
	conn := diag.NewUploadConn(data, func() error {
		log.Debug("diagnostics uploaded", "bytes", len(data))
		return commit()
	})
	b := newBridge(id, c, conn, conn.Abort)
	bridges[id] = b
	b.forget = func() { delete(bridges, id) }
	b.start(ctx, events)
	b.service(now)
	return b
}

// pathCarrier names the carrier bound to path id, or "".
func pathCarrier(carriers []*carrierState, id uint32) string {
	for _, cs := range carriers {
		if cs.bound && cs.path == id {
			return cs.Name
		}
	}
	return ""
}

// logPaths logs each path's state, for -status and the journal.
func logPaths(log *slog.Logger, level slog.Level, c *session.Client, carriers []*carrierState, now time.Time) {
	if c.State() != session.StateActive {
		return
	}
	for _, p := range c.Paths(now) {
		carrier := pathCarrier(carriers, p.ID)
		log.Log(context.Background(), level, "path", "id", p.ID, "carrier", carrier, "primary", p.Primary, "healthy", p.Healthy, "eligible", p.Eligible,
			"flows", p.Flows, "min_rtt", p.MinRTT.Round(100*time.Microsecond), "srtt", p.SRTT.Round(100*time.Microsecond),
			"loss", fmt.Sprintf("%.3f", p.Loss), "burst", fmt.Sprintf("%.1f", p.Burst),
			"stream_mbit", fmt.Sprintf("%.2f", p.StreamRate*8/1e6), "stream_inflight", p.StreamInflight, "capacity_mbit", fmt.Sprintf("%.1f", p.Capacity*8/1e6))
	}
}

// splitPacket reports whether an IPv4 packet from the TUN belongs to the
// userspace stack: a TCP packet of a split connection, or a SYN opening
// one that should be split.
func splitPacket(now time.Time, p []byte, flows map[splittcp.Flow]*splitFlow, want func(time.Time) bool) bool {
	f, syn, ok := splittcp.TCPFlow(p)
	if !ok {
		return false
	}
	if sf := flows[f]; sf != nil {
		sf.last = now
		return true
	}
	if !syn || !want(now) {
		return false
	}
	flows[f] = &splitFlow{last: now}
	return true
}
