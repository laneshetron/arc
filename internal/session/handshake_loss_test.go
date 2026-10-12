package session

import (
	"fmt"
	"sort"
	"testing"
	"time"
)

// establishTimes runs trials sessions at the given loss in each direction
// and returns how long each took to become active, sorted; trials that did
// not within limit are left out.
func establishTimes(t *testing.T, loss float64, trials int, limit time.Duration) []time.Duration {
	var times []time.Duration
	for i := range trials {
		n := newNetwork(t, uint64(5000+i), defaultRelayConfig(), ClientConfig{})
		n.up.loss, n.down.loss = loss, loss
		start := n.now
		if n.runUntil(limit, func() bool { return n.client.State() == StateActive }) {
			times = append(times, n.now.Sub(start))
		}
	}
	sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
	return times
}

// TestEstablishUnderLoss measures how quickly sessions become active at
// heavy loss in both directions on one path (run with -v for the table),
// and checks the two rows that the handshake retransmission schedule is
// meant to guarantee.
func TestEstablishUnderLoss(t *testing.T) {
	const trials = 200
	within, within60 := map[float64]int{}, map[float64]int{}
	for _, loss := range []float64{0.3, 0.5, 0.7, 0.8, 0.9} {
		times := establishTimes(t, loss, trials, 60*time.Second)
		count := func(d time.Duration) int {
			return sort.Search(len(times), func(i int) bool { return times[i] > d }) * 100 / trials
		}
		median := "-"
		if len(times) > trials/2 {
			median = times[trials/2].Round(100 * time.Millisecond).String()
		}
		within[loss], within60[loss] = count(10*time.Second), len(times)*100/trials
		t.Log(fmt.Sprintf("loss %2.0f%%: within 10 s %3d%%, 30 s %3d%%, 60 s %3d%%; median %s",
			loss*100, count(10*time.Second), count(30*time.Second), len(times)*100/trials, median))
	}
	// With INIT doubling from 1 s and AUTH on PTO backoff, these were 61%,
	// 18%, and 2%.
	if within[0.5] < 99 || within[0.7] < 95 || within60[0.9] < 80 {
		t.Errorf("established: %d%% within 10 s at 50%% loss, %d%% at 70%%, %d%% within 60 s at 90%%; "+
			"want >= 99%%, >= 95%%, >= 80%%", within[0.5], within[0.7], within60[0.9])
	}
}

func TestHandshakeSlowsWhenRelayIsSilent(t *testing.T) {
	n := newNetwork(t, 80, defaultRelayConfig(), ClientConfig{})
	n.up.down = true // the relay never hears the client
	inits := 0
	n.tap = func(toRelay bool, _ []byte) {
		if toRelay {
			inits++
		}
	}
	n.runFor(handshakeQuiet)
	fast := inits
	inits = 0
	n.runFor(time.Minute)
	t.Logf("INITs: %d in the first %v, %d in the next minute", fast, handshakeQuiet, inits)
	if fast < int(handshakeQuiet/handshakeRetransmit)-5 || inits > 65 {
		t.Errorf("sent %d INITs in the first %v and %d in the next minute; want about %d and at most 65",
			fast, handshakeQuiet, inits, handshakeQuiet/handshakeRetransmit)
	}
	// Hearing from the relay again restores the fast schedule.
	n.up.down = false
	if !n.runUntil(5*time.Second, func() bool { return n.client.State() == StateActive }) {
		t.Fatal("not established once the relay was reachable")
	}
}
