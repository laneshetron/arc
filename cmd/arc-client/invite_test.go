package main

import (
	"io"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/invite"
	"github.com/laneshetron/arc/internal/wire"
)

// TestPrintInvite: the request is kept until its invite is written, so a
// rerun after a failed write gets the same invite again.
func TestPrintInvite(t *testing.T) {
	p := &profile{dir: t.TempDir(), settings: map[string]string{}}
	req, err := pendingRequest(p, time.Now())
	if err != nil || req == [8]byte{} {
		t.Fatalf("request %x: %v", req, err)
	}
	tmpl := func() *invite.Invite {
		return &invite.Invite{Carriers: invite.CarrierUDP, Addr: netip.MustParseAddr("203.0.113.7"), UDPPort: 4433}
	}
	answer := &wire.Invite{RequestID: req, ID: [8]byte{1}, Secret: [16]byte{2}, Expires: uint32(time.Now().Add(time.Hour).Unix())}
	stdout := os.Stdout
	t.Cleanup(func() { os.Stdout = stdout })

	// A closed stdout: the write fails, and the request stays.
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	r.Close()
	os.Stdout = w
	if err := printInvite(p, tmpl(), answer); err == nil {
		t.Fatal("no error writing to a closed pipe")
	}
	w.Close()
	if again, err := pendingRequest(p, time.Now()); err != nil || again != req {
		t.Fatalf("after a failed write the request is %x (%v), want %x", again, err, req)
	}

	// Written: the request is forgotten.
	r, w, err = os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	if err := printInvite(p, tmpl(), answer); err != nil {
		t.Fatal(err)
	}
	w.Close()
	if out, _ := io.ReadAll(r); len(out) == 0 {
		t.Error("nothing written")
	}
	if _, err := os.Stat(p.path("invite-request")); !os.IsNotExist(err) {
		t.Errorf("request kept after the invite was written: %v", err)
	}
}
