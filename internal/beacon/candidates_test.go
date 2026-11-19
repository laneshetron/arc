package beacon

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// testPK is a public key to put in a Relay; these tests exercise ordering
// and retry state, never a signature.
var testPK = func() ed25519.PublicKey {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return pub
}()

func cand(addr string, enrolled bool, beacon string, notAfter time.Time) Candidate {
	return Candidate{
		Relay:    Relay{Addr: netip.MustParseAddr(addr), Key: testPK},
		Enrolled: enrolled,
		Beacon:   beacon,
		NotAfter: notAfter,
	}
}

// clock is a settable time source.
type clock struct{ t time.Time }

func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }

func TestCooldownDoubles(t *testing.T) {
	c := Cooldown{Base: 5 * time.Minute, Max: time.Hour}
	want := []time.Duration{
		0,
		5 * time.Minute,
		10 * time.Minute,
		20 * time.Minute,
		40 * time.Minute,
		time.Hour,
		time.Hour,
	}
	for i, w := range want {
		if got := c.delay(i); got != w {
			t.Errorf("delay(%d) = %s, want %s", i, got, w)
		}
	}
}

func TestCooldownDefaults(t *testing.T) {
	var c Cooldown
	if got := c.delay(1); got != 5*time.Minute {
		t.Errorf("first failure %s, want 5m", got)
	}
	if got := c.delay(10); got != time.Hour {
		t.Errorf("tenth failure %s, want 1h", got)
	}
}

func TestNextSkipsCoolingCandidates(t *testing.T) {
	clk := &clock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	a := cand("203.0.113.1", false, "b1._arcb.example.net", clk.t.Add(time.Hour))
	b := cand("203.0.113.2", false, "b1._arcb.example.net", clk.t.Add(time.Hour))
	l := NewList([]Candidate{a, b}, Cooldown{}, clk.now)

	got, err := l.Next()
	if err != nil {
		t.Fatal(err)
	}
	if got.Relay.Addr != a.Relay.Addr {
		t.Fatalf("first candidate is %s", got.Relay.Addr)
	}
	// §3.3's reason for per-candidate state: one dead relay at the front
	// must not cost a failed handshake every time.
	l.Failed(a)
	got, err = l.Next()
	if err != nil {
		t.Fatal(err)
	}
	if got.Relay.Addr != b.Relay.Addr {
		t.Fatalf("after failing the first, next is %s, want %s", got.Relay.Addr, b.Relay.Addr)
	}
	// And it comes back once the cooldown elapses.
	clk.advance(5*time.Minute + time.Second)
	got, err = l.Next()
	if err != nil {
		t.Fatal(err)
	}
	if got.Relay.Addr != a.Relay.Addr {
		t.Errorf("after the cooldown, first is %s", got.Relay.Addr)
	}
}

func TestSucceededClearsCooldown(t *testing.T) {
	clk := &clock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	a := cand("203.0.113.1", false, "b1", clk.t.Add(time.Hour))
	l := NewList([]Candidate{a}, Cooldown{}, clk.now)
	l.Failed(a)
	l.Failed(a)
	if got := l.Failures(a); got != 2 {
		t.Fatalf("%d failures", got)
	}
	if _, err := l.Next(); !errors.Is(err, ErrNoCandidate) {
		t.Fatalf("got %v, want ErrNoCandidate", err)
	}
	l.Succeeded(a)
	if got := l.Failures(a); got != 0 {
		t.Errorf("%d failures after success", got)
	}
	if _, err := l.Next(); err != nil {
		t.Errorf("not eligible after success: %v", err)
	}
}

func TestRepeatedFailuresExtendTheCooldown(t *testing.T) {
	clk := &clock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	a := cand("203.0.113.1", false, "b1", clk.t.Add(24*time.Hour))
	l := NewList([]Candidate{a}, Cooldown{}, clk.now)
	l.Failed(a)
	l.Failed(a)
	l.Failed(a) // 20 minutes
	if until := l.CooldownUntil(a); !until.Equal(clk.t.Add(20 * time.Minute)) {
		t.Fatalf("cooldown until %s", until)
	}
	clk.advance(19 * time.Minute)
	if _, err := l.Next(); !errors.Is(err, ErrNoCandidate) {
		t.Errorf("eligible while cooling: %v", err)
	}
	clk.advance(2 * time.Minute)
	if _, err := l.Next(); err != nil {
		t.Errorf("still cooling after 21 minutes: %v", err)
	}
}

func TestExpiredBeaconOnlyRelayIsRetired(t *testing.T) {
	clk := &clock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	// §3.4: a relay learned only from a beacon stops being usable for new
	// connections at not_after.
	a := cand("203.0.113.1", false, "b1", clk.t.Add(-time.Minute))
	l := NewList([]Candidate{a}, Cooldown{}, clk.now)
	if _, err := l.Next(); !errors.Is(err, ErrExpired) {
		t.Fatalf("got %v, want ErrExpired", err)
	}
}

func TestExpiredEnrolledRelayIsStillDialable(t *testing.T) {
	clk := &clock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	// §3.4's most important sentence: an independently enrolled pin is not
	// retired by any beacon. If it were, a beacon outage could lock a device
	// out of its own deployment.
	a := cand("203.0.113.1", true, "", time.Time{})
	l := NewList([]Candidate{a}, Cooldown{}, clk.now)
	if _, err := l.Next(); err != nil {
		t.Fatalf("enrolled relay refused: %v", err)
	}
}

func TestExpiredBeaconFallsThroughToTheEnrolledRelay(t *testing.T) {
	clk := &clock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	// Every beacon-only relay has expired, but the enrolled one has not: the
	// list must return it rather than ErrExpired.
	a := cand("203.0.113.1", true, "", time.Time{})
	b := cand("203.0.113.2", false, "b1", clk.t.Add(-time.Hour))
	l := NewList([]Candidate{a, b}, Cooldown{}, clk.now)
	got, err := l.Next()
	if err != nil {
		t.Fatal(err)
	}
	if got.Relay.Addr != a.Relay.Addr {
		t.Errorf("got %s", got.Relay.Addr)
	}
}

func TestSetKeepsRetryStateAcrossRereads(t *testing.T) {
	clk := &clock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	a := cand("203.0.113.1", false, "b1", clk.t.Add(24*time.Hour))
	l := NewList([]Candidate{a}, Cooldown{}, clk.now)
	l.Failed(a)
	// §3.3 re-reads the beacon hourly. If a re-read cleared the cooldown, a
	// dead relay would be retried first on every rotation.
	l.Set([]Candidate{a})
	if got := l.Failures(a); got != 1 {
		t.Errorf("%d failures after re-read", got)
	}
	if _, err := l.Next(); !errors.Is(err, ErrNoCandidate) {
		t.Errorf("re-read cleared the cooldown: %v", err)
	}
}

func TestFromBeaconsOrdersEnrolledFirst(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	enrolled := cand("203.0.113.1", true, "", time.Time{})
	b1 := &Beacon{NotAfter: now.Add(time.Hour), Relays: []Relay{
		{Addr: netip.MustParseAddr("203.0.113.2"), Key: testPK},
		{Addr: netip.MustParseAddr("203.0.113.3"), Key: testPK},
	}}
	b2 := &Beacon{NotAfter: now.Add(2 * time.Hour), Relays: []Relay{
		{Addr: netip.MustParseAddr("203.0.113.4"), Key: testPK},
	}}
	got := FromBeacons(&enrolled, map[string]*Beacon{
		"b1._arcb.example.net": b1,
		"b2._arcb.example.net": b2,
	}, []string{"b1._arcb.example.net", "b2._arcb.example.net"})

	want := []string{"203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"}
	if len(got) != len(want) {
		t.Fatalf("%d candidates, want %d", len(got), len(want))
	}
	for i, w := range want {
		if got[i].Relay.Addr.String() != w {
			t.Errorf("candidate %d is %s, want %s", i, got[i].Relay.Addr, w)
		}
	}
	if !got[0].Enrolled {
		t.Error("candidate 0 is not marked enrolled")
	}
	if got[3].Beacon != "b2._arcb.example.net" {
		t.Errorf("candidate 3 beacon %q", got[3].Beacon)
	}
}

func TestFromBeaconsKeepsTheEnrolledPin(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	addr := netip.MustParseAddr("203.0.113.1")
	enrolled := cand(addr.String(), true, "", time.Time{})
	// A beacon that also lists the enrolled relay must not downgrade it: the
	// enrolled entry never expires, and the same relay twice would make the
	// list try it twice.
	b := &Beacon{NotAfter: now.Add(time.Hour), Relays: []Relay{
		{Addr: addr, Key: testPK},
	}}
	got := FromBeacons(&enrolled, map[string]*Beacon{"b1": b}, []string{"b1"})
	if len(got) != 1 {
		t.Fatalf("%d candidates, want 1", len(got))
	}
	if !got[0].Enrolled {
		t.Error("the enrolled entry was replaced by the beacon's")
	}
}

func TestFromBeaconsWithoutEnrollment(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	b := &Beacon{NotAfter: now.Add(time.Hour), Relays: []Relay{
		{Addr: netip.MustParseAddr("203.0.113.2"), Key: testPK},
	}}
	got := FromBeacons(nil, map[string]*Beacon{"b1": b}, []string{"b1"})
	if len(got) != 1 {
		t.Fatalf("%d candidates", len(got))
	}
	if got[0].Enrolled {
		t.Error("beacon relay marked enrolled")
	}
}

func TestWatermarksRefuseAnOlderPublication(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	w := NewWatermarks(nil)
	if !w.Accept("b1", now) {
		t.Fatal("first publication refused")
	}
	// §3.4: an older record for the same name is refused even though it
	// verifies and has not expired, or a restart would reopen the replay
	// window.
	if w.Accept("b1", now.Add(-time.Minute)) {
		t.Error("older publication accepted")
	}
	if !w.Accept("b1", now.Add(time.Minute)) {
		t.Error("newer publication refused")
	}
}

func TestWatermarksArePerName(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	w := NewWatermarks(nil)
	w.Accept("b1", now)
	// §3.4's failover case: b1 advances, b2 is older but names the relay
	// that works. A shared watermark would discard b2 as a rollback and the
	// client would never reach it.
	if !w.Accept("b2", now.Add(-time.Hour)) {
		t.Error("a fresh b1 shadowed a still-valid b2")
	}
}

func TestWatermarksPersist(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	w := NewWatermarks(map[string]time.Time{"b1": now})
	if w.Accept("b1", now.Add(-time.Second)) {
		t.Error("a record older than the persisted watermark was accepted")
	}
	snap := w.Snapshot()
	if !snap["b1"].Equal(now) {
		t.Errorf("snapshot has %s", snap["b1"])
	}
	// The snapshot is a copy: mutating it must not affect the guard.
	snap["b1"] = now.Add(-time.Hour)
	if w.Accept("b1", now.Add(-time.Second)) {
		t.Error("mutating the snapshot weakened the watermark")
	}
}

func TestVerifyAppliesTheWatermarkOnlyAfterVerification(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	pub, priv := testKey(t)
	b := oneRelay(t, now)
	b.Published = now.Add(-time.Hour)
	content, err := Encode(b, Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWatermarks(nil)

	// An unsigned record must not advance the watermark, or a forgery would
	// be able to lock out the genuine next publication for that name.
	unsigned := Prefix + "AAAA"
	if _, err := Verify(unsigned, "b1", Suffix(testZone), pub, now, w); err == nil {
		t.Fatal("unsigned record accepted")
	}
	if len(w.Snapshot()) != 0 {
		t.Error("watermark advanced by a record that failed verification")
	}

	if _, err := Verify(content, "b1", Suffix(testZone), pub, now, w); err != nil {
		t.Fatal(err)
	}
	if got := w.Snapshot()["b1"]; !got.Equal(b.Published) {
		t.Errorf("watermark is %s, want %s", got, b.Published)
	}
}

func TestVerifyRefusesARollback(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	pub, priv := testKey(t)
	older := oneRelay(t, now)
	older.Published = now.Add(-2 * time.Hour)
	newer := oneRelay(t, now)
	newer.Published = now.Add(-time.Hour)
	olderContent, err := Encode(older, Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	newerContent, err := Encode(newer, Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	w := NewWatermarks(nil)
	if _, err := Verify(newerContent, "b1", Suffix(testZone), pub, now, w); err != nil {
		t.Fatal(err)
	}
	_, err = Verify(olderContent, "b1", Suffix(testZone), pub, now, w)
	if !errors.Is(err, errRollback) {
		t.Fatalf("got %v, want errRollback", err)
	}
}

func TestVerifyWithoutWatermarks(t *testing.T) {
	now := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	pub, priv := testKey(t)
	content, err := Encode(oneRelay(t, now), Suffix(testZone), priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(content, "b1", Suffix(testZone), pub, now, nil); err != nil {
		t.Fatal(err)
	}
}

func TestSortedNamesIsStable(t *testing.T) {
	m := map[string]*Beacon{"c": nil, "a": nil, "b": nil}
	got := SortedNames(m)
	want := []string{"a", "b", "c"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v", got)
		}
	}
}

func TestListIsSafeForConcurrentUse(t *testing.T) {
	// The doc comment claims concurrent safety because a session goroutine
	// reports outcomes while another asks what to try next. Under -race this
	// fails if the claim is not true.
	clk := &clock{t: time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)}
	var cands []Candidate
	for i := range 8 {
		cands = append(cands, cand(fmt.Sprintf("203.0.113.%d", i+1), false, "b1", clk.t.Add(24*time.Hour)))
	}
	l := NewList(cands, Cooldown{Base: time.Millisecond}, clk.now)
	done := make(chan struct{})
	var wg sync.WaitGroup
	for i := range 4 {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			for range 50 {
				c, err := l.Next()
				if err == nil {
					l.Failed(c)
				}
			}
		}(i)
		go func(i int) {
			defer wg.Done()
			for range 50 {
				l.Set(cands)
				l.Succeeded(cands[i])
				_ = l.Candidates()
				_ = l.Failures(cands[i])
				_ = l.CooldownUntil(cands[i])
			}
		}(i)
	}
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("timed out")
	}
}

func TestWatermarksAreSafeForConcurrentUse(t *testing.T) {
	w := NewWatermarks(nil)
	base := time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)
	var wg sync.WaitGroup
	for i := range 8 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := range 50 {
				w.Accept(fmt.Sprintf("b%d", i%2), base.Add(time.Duration(j)*time.Second))
				_ = w.Snapshot()
			}
		}(i)
	}
	wg.Wait()
}
