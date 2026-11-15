package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"text/tabwriter"
	"time"

	"github.com/laneshetron/arc/internal/accounts"
	"github.com/laneshetron/arc/internal/crypto"
	"github.com/laneshetron/arc/internal/engine"
	"github.com/laneshetron/arc/internal/session"
	"github.com/laneshetron/arc/internal/wire"
)

// Devices managing devices (self-service-accounts.md §3.8).

// managerFlags are the flags devices and revoke share.
type managerFlags struct {
	dir     *string
	timeout *time.Duration
	binds   []string
}

func newManagerFlags(fs *flag.FlagSet) *managerFlags {
	m := &managerFlags{
		dir:     fs.String("profile", "profile", "this device's profile, as arc-client enroll wrote it"),
		timeout: fs.Duration("timeout", 2*time.Minute, "give up after this long"),
	}
	fs.Func("bind", "bind a carrier socket to this interface (repeatable)", func(iface string) error {
		if iface == "" {
			return errors.New("interface name must not be empty")
		}
		m.binds = append(m.binds, iface)
		return nil
	})
	return m
}

// newRequestID returns a random, nonzero request ID.
func newRequestID() [8]byte {
	var id [8]byte
	for id == [8]byte{} {
		rand.Read(id[:])
	}
	return id
}

var errThisRevoked = errors.New("this device has been revoked")

var errNoManage = errors.New("the relay does not let this device manage devices (its account may not, or the device enrolled without a key; ask the operator)")

// exchange runs req with the relay as the profile's device, until it
// ends, the timeout passes, or the session ends.
func (m *managerFlags) exchange(req func(static crypto.StaticKey) *engine.Request) error {
	p, static, token, unlock, err := openEnrolled(*m.dir)
	if err != nil {
		return err
	}
	defer unlock()
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *m.timeout)
	defer cancel()
	err = connectOnce(ctx, log, p, m.binds, static, token, func(cfg *engine.ClientConfig) {
		cfg.Request = req(static)
	})
	switch {
	case errors.Is(err, errAnswered):
		return nil
	case errors.Is(err, session.ErrNoDevices):
		return errNoManage
	case errors.Is(err, session.ErrRevoked):
		return errThisRevoked
	case ctx.Err() != nil && !errors.Is(ctx.Err(), context.Canceled):
		return fmt.Errorf("no answer after %v", *m.timeout)
	}
	return err
}

// devicesRequest is a Request for the account's devices, which go to
// answer.
func devicesRequest(answer func(wire.Devices) error) *engine.Request {
	id := newRequestID()
	return &engine.Request{
		Send: func(c *session.Client) error { return c.RequestDevices(id) },
		Answer: func(e session.ClientEvent) (bool, error) {
			a, ok := e.(session.DevicesAnswer)
			if !ok || a.RequestID != id {
				return true, nil
			}
			if a.Status != 0 {
				return false, errNoManage
			}
			return false, answer(a.Devices)
		},
	}
}

// devicesCmd lists the account's devices, as a tree of who invited whom.
func devicesCmd(args []string) error {
	fs := flag.NewFlagSet("devices", flag.ExitOnError)
	m := newManagerFlags(fs)
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), "usage: arc-client devices [flags]\nlists this device's account's devices, each under the device that invited it")
		fs.PrintDefaults()
	}
	fs.Parse(args)
	if fs.NArg() != 0 {
		fs.Usage()
		os.Exit(2)
	}
	return m.exchange(func(static crypto.StaticKey) *engine.Request {
		return devicesRequest(func(d wire.Devices) error {
			printDevices(os.Stdout, d.Devices, static.Public[:8], time.Now())
			return errAnswered
		})
	})
}

// printDevices writes the devices as a tree, each under its parent,
// marking the one whose key begins with self.
func printDevices(w io.Writer, devices []wire.DeviceInfo, self []byte, now time.Time) {
	listed := map[[8]byte]bool{}
	for _, d := range devices {
		listed[d.ID] = true
	}
	children := map[[8]byte][]wire.DeviceInfo{}
	var roots []wire.DeviceInfo
	for _, d := range devices {
		if d.Parent == ([8]byte{}) || !listed[d.Parent] {
			roots = append(roots, d)
		} else {
			children[d.Parent] = append(children[d.Parent], d)
		}
	}
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "DEVICE\tKEY\tENROLLED\tLAST SEEN")
	var walk func(d wire.DeviceInfo, depth int)
	walk = func(d wire.DeviceInfo, depth int) {
		name := strings.Repeat("  ", depth) + d.Name
		if bytes.Equal(d.Key[:], self) {
			name += " (this device)"
		}
		if depth == 0 && d.Parent != ([8]byte{}) {
			name += " (its inviter is revoked)"
		}
		key := "unbound"
		if d.Key != ([8]byte{}) {
			key = fmt.Sprintf("%x", d.Key)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", name, key, day(d.Created), seen(d.LastSeen, now))
		for _, c := range children[d.ID] {
			walk(c, depth+1)
		}
	}
	for _, d := range roots {
		walk(d, 0)
	}
	tw.Flush()
}

func day(unix uint32) string { return time.Unix(int64(unix), 0).Format("2006-01-02 15:04") }

func seen(unix uint32, now time.Time) string {
	switch {
	case unix == 0:
		return "-"
	case now.Unix()-int64(unix) < 60:
		return "now"
	}
	return day(unix)
}

// revokeCmd revokes a device of the account by name, from this device:
// first the device list, to find it, then the revocation.
func revokeCmd(args []string) error {
	fs := flag.NewFlagSet("revoke", flag.ExitOnError)
	m := newManagerFlags(fs)
	descendants := fs.Bool("descendants", false, "also revoke every device enrolled through its invites, and theirs in turn")
	fs.Usage = func() {
		fmt.Fprintln(fs.Output(), `usage: arc-client revoke [flags] DEVICE
revokes a device of this device's account (arc-client devices lists them);
this device may revoke itself. The operator can undo it for 7 days.`)
		fs.PrintDefaults()
	}
	// Flags may come before or after the device.
	var rest []string
	for len(args) > 0 {
		fs.Parse(args)
		if args = fs.Args(); len(args) > 0 {
			rest, args = append(rest, args[0]), args[1:]
		}
	}
	if len(rest) != 1 {
		fs.Usage()
		os.Exit(2)
	}
	// The relay remembers a revocation it did for 10 minutes
	// (gateway.RevokeMemory), to answer its repeats as done; repeats past
	// that would be judged afresh.
	if *m.timeout > 10*time.Minute {
		return errors.New("-timeout: at most 10m for revoke")
	}
	name := rest[0]
	var target, me *wire.DeviceInfo
	err := m.exchange(func(static crypto.StaticKey) *engine.Request {
		list := devicesRequest(func(d wire.Devices) error {
			for i, x := range d.Devices {
				if x.Name == name {
					target = &d.Devices[i]
				}
				if bytes.Equal(x.Key[:], static.Public[:8]) {
					me = &d.Devices[i]
				}
			}
			if target == nil {
				return fmt.Errorf("the account has no device %s (arc-client devices lists them)", name)
			}
			return nil
		})
		id := newRequestID()
		return &engine.Request{
			Send: func(c *session.Client) error {
				if target == nil {
					return list.Send(c)
				}
				return c.RequestRevoke(id, target.ID, *descendants)
			},
			Answer: func(e session.ClientEvent) (bool, error) {
				if target == nil {
					more, err := list.Answer(e)
					return more || (err == nil && target != nil), err
				}
				a, ok := e.(session.RevokeAnswer)
				if !ok || a.RequestID != id {
					return true, nil
				}
				if a.Status != 0 {
					return false, revokeRefusal(me, time.Now())
				}
				return false, errAnswered
			},
		}
	})
	// Revoking this device closes its session with REVOKED.
	if errors.Is(err, errThisRevoked) && target != nil && target == me {
		err = nil
	}
	if err != nil {
		return err
	}
	what := "revoked " + name
	if *descendants {
		what += " and every device enrolled through its invites"
	}
	fmt.Println(what + "; the operator can restore it within 7 days")
	return nil
}

// revokeRefusal explains a refused revocation, by what this device, me,
// can tell of itself.
func revokeRefusal(me *wire.DeviceInfo, now time.Time) error {
	if me != nil {
		if age := now.Sub(time.Unix(int64(me.Created), 0)); age < accounts.CoolingOff {
			return fmt.Errorf("the relay refused: a device may revoke others only once enrolled for %d hours, and this one has been for %s",
				int(accounts.CoolingOff.Hours()), age.Truncate(time.Minute))
		}
	}
	return errors.New("the relay refused: this device may not revoke that one")
}
