package session

import (
	"net/netip"
	"time"
)

const maxHandshakeSources = 4096

type handshakeBucket struct {
	tokens float64
	at     time.Time
}

func (b *handshakeBucket) available(now time.Time, rate int) bool {
	if b.at.IsZero() {
		b.tokens, b.at = float64(rate), now
	}
	if now.After(b.at) {
		b.tokens = min(float64(rate), b.tokens+now.Sub(b.at).Seconds()*float64(rate))
		b.at = now
	}
	return b.tokens >= 1
}

// Source state is capped independently of the global work bucket, so
// spoofed addresses cannot grow admission memory without bound.
type handshakeAdmission struct {
	global  handshakeBucket
	sources map[netip.Addr]*handshakeBucket
	sweepAt time.Time
}

func (a *handshakeAdmission) allow(now time.Time, source netip.Addr, globalRate, sourceRate int) bool {
	if !a.global.available(now, globalRate) {
		return false
	}
	if a.sources == nil {
		a.sources = make(map[netip.Addr]*handshakeBucket)
	}
	if !now.Before(a.sweepAt) {
		for ip, b := range a.sources {
			if now.Sub(b.at) >= time.Minute {
				delete(a.sources, ip)
			}
		}
		a.sweepAt = now.Add(time.Second)
	}
	b := a.sources[source]
	if b == nil {
		if len(a.sources) >= maxHandshakeSources {
			return false
		}
		b = &handshakeBucket{}
		a.sources[source] = b
	}
	if !b.available(now, sourceRate) {
		return false
	}
	a.global.tokens--
	b.tokens--
	return true
}
