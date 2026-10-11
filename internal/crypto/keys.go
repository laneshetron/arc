package crypto

import (
	"errors"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

// Epoch parameters (§13).
const (
	RekeyAfterTime    = 120 * time.Second
	RekeyAfterPackets = 1 << 32
	KeyOverlap        = 60 * time.Second
	IntegrityLimit    = 1 << 36
)

// ErrEpoch is returned for a packet whose epoch_low cannot be resolved to
// a usable key.
var ErrEpoch = errors.New("crypto: unknown epoch")

// SendKeys is one direction's sending key schedule.
type SendKeys struct {
	epoch   uint64
	key     [32]byte
	aead    *AEAD
	started time.Time
	packets uint64
}

func NewSendKeys(key [32]byte, now time.Time) *SendKeys {
	return &SendKeys{key: key, aead: NewAEAD(key), started: now}
}

func (s *SendKeys) Epoch() uint64 { return s.epoch }

// Seal sets the header's epoch_low and appends the protected packet to dst.
func (s *SendKeys) Seal(dst []byte, h wire.DataHeader, pathID uint32, plaintext []byte) []byte {
	h.EpochLow = uint8(s.epoch)
	s.packets++
	return s.aead.SealData(dst, h, pathID, plaintext)
}

// RekeyDue reports whether the current key has reached its time or packet
// limit. The session must also have had a packet from the current epoch
// acknowledged before calling Advance (§13).
func (s *SendKeys) RekeyDue(now time.Time) bool {
	return now.Sub(s.started) >= RekeyAfterTime || s.packets >= RekeyAfterPackets
}

// Advance moves to the next epoch and erases the old key.
func (s *SendKeys) Advance(now time.Time) {
	next := Rekey(s.key)
	clear(s.key[:])
	s.key = next
	s.aead = NewAEAD(next)
	s.epoch++
	s.started = now
	s.packets = 0
}

// RecvKeys is one direction's receiving key schedule: the current epoch,
// the previous epoch during its overlap period, and a lazily derived next
// epoch that is committed only after a packet authenticates under it.
type RecvKeys struct {
	epoch     uint64
	key       [32]byte
	cur       *AEAD
	prev      *AEAD
	prevUntil time.Time
	next      *AEAD
	nextKey   [32]byte
	failures  uint64
}

func NewRecvKeys(key [32]byte) *RecvKeys {
	return &RecvKeys{key: key, cur: NewAEAD(key)}
}

func (r *RecvKeys) Epoch() uint64 { return r.epoch }

// Open resolves the packet's epoch, authenticates and decrypts it, and on
// success commits a pending epoch change. It returns the epoch the packet
// belonged to. Replay checks are the caller's job and must bracket Open:
// check before, record after success (§13).
func (r *RecvKeys) Open(dst []byte, h wire.DataHeader, aad []byte, pathID uint32, ciphertext []byte, now time.Time) ([]byte, uint64, error) {
	if r.prev != nil && !now.Before(r.prevUntil) {
		r.prev = nil
	}
	var (
		a     *AEAD
		epoch uint64
	)
	switch h.EpochLow {
	case uint8(r.epoch):
		a, epoch = r.cur, r.epoch
	case uint8(r.epoch + 1):
		if r.next == nil {
			r.nextKey = Rekey(r.key)
			r.next = NewAEAD(r.nextKey)
		}
		a, epoch = r.next, r.epoch+1
	case uint8(r.epoch - 1):
		if r.prev == nil || r.epoch == 0 {
			return dst, 0, ErrEpoch
		}
		a, epoch = r.prev, r.epoch-1
	default:
		return dst, 0, ErrEpoch
	}

	out, err := a.OpenData(dst, h, aad, pathID, ciphertext)
	if err != nil {
		r.failures++
		return dst, 0, err
	}
	if epoch == r.epoch+1 {
		r.prev, r.prevUntil = r.cur, now.Add(KeyOverlap)
		r.cur, r.next = r.next, nil
		clear(r.key[:])
		r.key, r.nextKey = r.nextKey, [32]byte{}
		r.epoch++
	}
	return out, epoch, nil
}

// IntegrityLimitReached reports whether the session must be closed because
// too many packets failed authentication (§13).
func (r *RecvKeys) IntegrityLimitReached() bool { return r.failures >= IntegrityLimit }
