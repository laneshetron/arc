package stream

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

// waitCounts polls the front's admission until cond holds.
func waitCounts(t *testing.T, f *Front, what string, cond func(conns, pending int) bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		conns, pending, _, _ := f.adm.counts()
		if cond(conns, pending) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %d connections, %d pending", what, conns, pending)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// closedSoon reports whether the server closes c within a second.
func closedSoon(c net.Conn) bool {
	c.SetReadDeadline(time.Now().Add(time.Second))
	_, err := c.Read(make([]byte, 1))
	return err == io.EOF
}

func TestFrontPendingPerSourceLimit(t *testing.T) {
	// Connections that never start TLS hold pending permits; one past
	// the per-source budget is closed before any TLS work.
	f, _ := startFront(t, func(o *FrontOptions) { o.MaxPendingPerSource = 2 })
	var held []net.Conn
	for range 2 {
		c, err := net.Dial("tcp", f.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		held = append(held, c)
	}
	waitCounts(t, f, "two held", func(conns, pending int) bool { return conns == 2 && pending == 2 })
	extra, err := net.Dial("tcp", f.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer extra.Close()
	if !closedSoon(extra) {
		t.Fatal("connection past the per-source pending limit stayed open")
	}
	for _, c := range held {
		c.Close()
	}
	waitCounts(t, f, "after close", func(conns, pending int) bool { return conns == 0 && pending == 0 })
}

func TestFrontHandshakeTimeoutReleasesPermit(t *testing.T) {
	f, _ := startFront(t, func(o *FrontOptions) { o.HandshakeTimeout = 50 * time.Millisecond })
	c, err := net.Dial("tcp", f.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if !closedSoon(c) {
		t.Fatal("silent connection outlived the handshake timeout")
	}
	waitCounts(t, f, "after timeout", func(conns, pending int) bool { return conns == 0 && pending == 0 })
}

func TestFrontIdleVisitorReleasesPermit(t *testing.T) {
	f, _ := startFront(t, func(o *FrontOptions) { o.VisitorIdle = 100 * time.Millisecond })
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Get("https://" + f.Addr().String() + "/")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	// The client keeps the connection alive; the front must not.
	waitCounts(t, f, "idle visitor", func(conns, pending int) bool { return conns == 0 && pending == 0 })
}

func TestFrontCarrierLeavesPendingBudget(t *testing.T) {
	// With one pending slot, an upgraded carrier must not keep holding
	// it: visitors still get in while the carrier runs.
	f, _, _ := frontPair(t, func(o *FrontOptions) { o.MaxPending = 1 })
	waitCounts(t, f, "carrier up", func(conns, pending int) bool { return conns == 1 && pending == 0 })
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr, Timeout: 2 * time.Second}).Get("https://" + f.Addr().String() + "/")
	if err != nil {
		t.Fatalf("visitor refused while a carrier runs: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("visitor got %s", resp.Status)
	}
}
