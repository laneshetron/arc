// Command libarc is the ARC tunnel client as a C library, for a
// NetworkExtension packet tunnel provider on macOS and iOS. Build it with
// -buildmode=c-archive; arc.h is its interface.
//
// This file holds the library's logic in plain Go, so it is tested on
// every platform; export_darwin.go is the C interface over it.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/laneshetron/arc/internal/client"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/diag"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/keyfile"
)

func main() {}

// config is arc_start's config_json; arc.h documents each member.
type config struct {
	Relay      string `json:"relay"`
	RelayKey   string `json:"relay_key"`
	Token      string `json:"token"`
	PrivateKey string `json:"private_key"`

	NoUDP             bool   `json:"no_udp"`
	Censorship        bool   `json:"censorship"`
	TLS               string `json:"tls"`
	TLSCA             string `json:"tls_ca"`
	TLSServerName     string `json:"tls_server_name"`
	TLSCover          string `json:"tls_cover"`
	TLSFingerprint    string `json:"tls_fingerprint"`
	TLSFragment       int    `json:"tls_fragment"`
	Front             string `json:"front"`
	StreamRotateBytes int64  `json:"stream_rotate_bytes"`

	Redundancy     string `json:"redundancy"`
	FEC            string `json:"fec"`
	SplitTCP       string `json:"split_tcp"`
	StatusInterval int    `json:"status_interval"`

	LogLevel         string `json:"log_level"`
	Journal          string `json:"journal"`
	ShareDiagnostics bool   `json:"share_diagnostics"`
}

func parseConfig(data []byte) (config, error) {
	c := config{Redundancy: "off", FEC: "auto", SplitTCP: "off", LogLevel: "info"}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&c); err != nil {
		return c, fmt.Errorf("config: %w", err)
	}
	if dec.More() {
		return c, errors.New("config: more than one JSON value")
	}
	return c, nil
}

// clientConfig is c as a client.Config, without its logger, journal and
// OnNetwork, which start provides.
func (c config) clientConfig() (client.Config, error) {
	var cc client.Config
	var err error
	if cc.Relay, err = netip.ParseAddrPort(c.Relay); err != nil {
		return cc, fmt.Errorf("relay: %w", err)
	}
	if cc.RelayKey, err = keyfile.Decode32(c.RelayKey); err != nil {
		return cc, fmt.Errorf("relay_key: %w", err)
	}
	if c.Token == "" {
		return cc, errors.New("token: missing")
	}
	cc.Token = []byte(c.Token)
	priv, err := keyfile.Decode32(c.PrivateKey)
	if err != nil {
		return cc, fmt.Errorf("private_key: %w", err)
	}
	if cc.Static, err = keyfile.StaticFromPrivate(priv); err != nil {
		return cc, fmt.Errorf("private_key: %w", err)
	}
	if cc.Redundancy, err = client.ParseRedundancy(c.Redundancy); err != nil {
		return cc, fmt.Errorf("redundancy: %w", err)
	}
	if cc.FEC, err = client.ParseFEC(c.FEC); err != nil {
		return cc, fmt.Errorf("fec: %w", err)
	}
	if cc.SplitTCP, err = client.ParseSplitTCP(c.SplitTCP); err != nil {
		return cc, fmt.Errorf("split_tcp: %w", err)
	}
	if c.StatusInterval < 0 {
		return cc, errors.New("status_interval: negative")
	}
	cc.StatusInterval = time.Duration(c.StatusInterval) * time.Second
	// No binds and no full-tunnel setup: the provider's sockets already
	// bypass the tunnel, and the provider routes everything else.
	cc.Carriers = client.CarrierOptions{
		NoUDP: c.NoUDP, Censorship: c.Censorship,
		TLS: c.TLS, TLSCA: c.TLSCA, TLSName: c.TLSServerName, TLSCover: c.TLSCover,
		TLSFingerprint: c.TLSFingerprint, TLSFragment: c.TLSFragment,
		Front: c.Front, RotateBytes: c.StreamRotateBytes,
	}
	return cc, nil
}

func (c config) level() (slog.Level, error) {
	var l slog.Level
	if err := l.UnmarshalText([]byte(c.LogLevel)); err != nil {
		return 0, fmt.Errorf("log_level: %w", err)
	}
	return l, nil
}

// emitter delivers a tunnel's events to the app one at a time, and none
// after it is closed.
type emitter struct {
	mu     sync.Mutex
	fn     func(event []byte) int
	closed bool
}

func (e *emitter) emit(event []byte) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return 0
	}
	return e.fn(event)
}

// emitJSON marshals v as an event. Every event's members are plain values,
// so marshaling cannot fail.
func (e *emitter) emitJSON(v any) int {
	b, _ := json.Marshal(v)
	return e.emit(b)
}

// closeWith delivers a last event and closes e.
func (e *emitter) closeWith(v any) {
	b, _ := json.Marshal(v)
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.closed {
		e.fn(b)
		e.closed = true
	}
}

// Write takes one JSON log record from slog.JSONHandler, which writes each
// record with a single Write.
func (e *emitter) Write(p []byte) (int, error) {
	e.emit(bytes.TrimRight(p, "\n"))
	return len(p), nil
}

type networkEvent struct {
	Event   string `json:"event"`
	Address string `json:"address"`
	Prefix  int    `json:"prefix"`
	MTU     int    `json:"mtu"`
	DNS     string `json:"dns"`
}

type stoppedEvent struct {
	Event string `json:"event"`
	Error string `json:"error,omitempty"`
}

// device is the packet device a tunnel runs over, which it closes when it
// stops.
type device interface {
	engine.PacketDevice
	Close() error
}

// tunnel is a running client.
type tunnel struct {
	cancel context.CancelFunc
	done   chan struct{} // closed once the run has ended and the stopped event is out
	events *emitter
}

// start runs a client from config_json over dev, sending its events to fn.
// The tunnel closes dev when it stops, and start closes it when it fails.
func start(configJSON []byte, dev device, fn func(event []byte) int) (*tunnel, error) {
	cfg, err := parseConfig(configJSON)
	var cc client.Config
	if err == nil {
		cc, err = cfg.clientConfig()
	}
	var level slog.Level
	if err == nil {
		level, err = cfg.level()
	}
	if err != nil {
		dev.Close()
		return nil, err
	}
	events := &emitter{fn: fn}
	log := slog.New(slog.NewJSONHandler(events, &slog.HandlerOptions{Level: level}).
		WithAttrs([]slog.Attr{slog.String("event", "log")}))
	var journal *diag.Journal
	if cfg.Journal != "" {
		// As in arc-client: the journal is bound to this relay, and a
		// journal that won't open never keeps the tunnel down.
		journal, err = diag.OpenJournal(cfg.Journal, base64.StdEncoding.EncodeToString(cc.RelayKey[:]), 0)
		if err != nil {
			log.Warn("running without a diagnostics journal", "journal", cfg.Journal, "err", err)
			journal = nil
		} else {
			log = diag.Tee(log.Handler(), journal.Handler())
			if n := journal.Discarded(); n > 0 {
				log.Warn("journal held another relay's diagnostics; discarded them", "journal", cfg.Journal, "bytes", n)
			}
		}
	}
	if cfg.ShareDiagnostics {
		cc.Diagnostics = journal
	}
	cc.Logger = log
	cc.OnNetwork = func(n client.Network) error {
		ev := networkEvent{Event: "network", Address: n.Addr.Addr().String(), Prefix: n.Addr.Bits(), MTU: n.MTU}
		if !n.DNS.IsUnspecified() {
			ev.DNS = n.DNS.String()
		}
		if rc := events.emitJSON(ev); rc != 0 {
			return fmt.Errorf("the app failed to apply the network settings (code %d)", rc)
		}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	t := &tunnel{cancel: cancel, done: make(chan struct{}), events: events}
	go func() {
		defer close(t.done)
		err := client.Run(ctx, cc, dev)
		dev.Close()
		if journal != nil {
			journal.Close()
		}
		ev := stoppedEvent{Event: "stopped"}
		if err != nil {
			ev.Error = err.Error()
		}
		events.closeWith(ev)
	}()
	return t, nil
}

// stop ends the tunnel and waits until it has, its stopped event included.
func (t *tunnel) stop() {
	t.cancel()
	<-t.done
}

// generateKey is arc_generate_key's answer.
func generateKey() ([]byte, error) {
	k, err := crypto.GenerateStaticKey(nil)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Private string `json:"private_key"`
		Public  string `json:"public_key"`
	}{keyfile.Encode(k.Private), keyfile.Encode(k.Public)})
}
