package engine

import (
	"bytes"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"
)

// TestSendFailedRateLimited checks that a carrier whose sends keep failing
// logs a warning at most every sendWarnInterval, counting the failures in
// between, rather than one per flush.
func TestSendFailedRateLimited(t *testing.T) {
	var buf bytes.Buffer
	log := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			if a.Key == slog.TimeKey {
				return slog.Attr{}
			}
			return a
		},
	}))
	cs := &carrierState{Carrier: Carrier{Name: "en0"}}
	err := errors.New("sendmsg: can't assign requested address")
	start := time.Now()
	// 1000 flushes a millisecond apart: warnings at 0 s and 2 s.
	for i := range 1000 {
		cs.sendFailed(log, start.Add(time.Duration(i)*time.Millisecond), err)
	}
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	want := []string{
		`level=WARN msg="send failed" carrier=en0 err="sendmsg: can't assign requested address" failures=1`,
		`level=WARN msg="send failed" carrier=en0 err="sendmsg: can't assign requested address" failures=2000`,
	}
	if len(lines) != 1 || lines[0] != want[0] {
		t.Fatalf("after 1 s of failures, logged:\n%s\nwant:\n%s", buf.String(), want[0])
	}
	for i := 1000; i <= 3000; i++ {
		cs.sendFailed(log, start.Add(time.Duration(i)*time.Millisecond), err)
	}
	lines = strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 || lines[1] != want[1] {
		t.Fatalf("after 3 s of failures, logged:\n%s\nwant the second line:\n%s", buf.String(), want[1])
	}
}
