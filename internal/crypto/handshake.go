// Package crypto implements ARC/1 session cryptography (spec §8.6, §9,
// §13, §14.7): the Noise IK handshake, DATA packet protection with
// explicit per-path nonces, epoch rekeying, replay windows, cookies, and
// stateless reset tokens.
package crypto

import (
	"bytes"
	"crypto/rand"
	"errors"
	"io"

	"github.com/flynn/noise"

	"github.com/laneshetron/arc/internal/wire"
)

var cipherSuite = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

// StaticKey is an X25519 static key pair.
type StaticKey = noise.DHKey

// GenerateStaticKey creates a static key pair. A nil reader uses crypto/rand.
func GenerateStaticKey(r io.Reader) (StaticKey, error) {
	if r == nil {
		r = rand.Reader
	}
	return cipherSuite.GenerateKeypair(r)
}

// TrafficKeys are the epoch-0 directional keys from Noise Split().
type TrafficKeys struct {
	Send, Recv [32]byte
}

const msg2PayloadLen = 8 + 16 // relay_cid || reset_token

var (
	ErrHandshake = errors.New("crypto: handshake failed")
	errPayload   = errors.New("crypto: unexpected handshake payload")
)

// ClientConfig configures the initiator side of a handshake.
type ClientConfig struct {
	Static      StaticKey
	RelayPublic []byte // pinned relay static public key
	SenderCID   wire.CID
	Rand        io.Reader // ephemeral key source; nil uses crypto/rand
}

// ClientHandshake is one handshake attempt. Its HANDSHAKE_INIT bytes are
// fixed, so retransmissions are byte-identical (§9.2).
type ClientHandshake struct {
	cfg          ClientConfig
	ephemeralKey [32]byte // X25519 private key, replayed into each rebuilt state
	init         wire.HandshakeInit
}

// ClientResult is what the client learns from a completed handshake.
type ClientResult struct {
	Keys       TrafficKeys
	RelayCID   wire.CID
	ResetToken wire.Token
}

func NewClientHandshake(cfg ClientConfig) (*ClientHandshake, error) {
	r := cfg.Rand
	if r == nil {
		r = rand.Reader
	}
	h := &ClientHandshake{cfg: cfg}
	if _, err := io.ReadFull(r, h.ephemeralKey[:]); err != nil {
		return nil, err
	}
	h.init.Version = wire.Version1
	h.init.SenderCID = cfg.SenderCID
	_, msg1, err := h.start()
	if err != nil {
		return nil, err
	}
	copy(h.init.NoiseMsg1[:], msg1)
	return h, nil
}

// start builds a handshake state that has written message 1. It is rebuilt
// for every response, so a forged HANDSHAKE_RESP cannot corrupt the state
// used to process the genuine one.
func (h *ClientHandshake) start() (*noise.HandshakeState, []byte, error) {
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        bytes.NewReader(h.ephemeralKey[:]), // flynn/noise draws e from Random
		Pattern:       noise.HandshakeIK,
		Initiator:     true,
		Prologue:      h.init.Prologue(),
		StaticKeypair: h.cfg.Static,
		PeerStatic:    h.cfg.RelayPublic,
	})
	if err != nil {
		return nil, nil, err
	}
	msg1, _, _, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	if len(msg1) != wire.NoiseMsg1Len {
		return nil, nil, ErrHandshake
	}
	return hs, msg1, nil
}

// Init returns the HANDSHAKE_INIT packet, with a cookie if one was supplied.
func (h *ClientHandshake) Init(cookie *[wire.CookieLen]byte) wire.HandshakeInit {
	p := h.init
	if cookie != nil {
		p.Cookie = *cookie
	}
	return p
}

// Finish processes a HANDSHAKE_RESP. A failure leaves the handshake usable
// for a later, genuine response.
func (h *ClientHandshake) Finish(resp *wire.HandshakeResp) (ClientResult, error) {
	var res ClientResult
	if resp.DestCID != h.cfg.SenderCID {
		return res, ErrHandshake
	}
	hs, _, err := h.start()
	if err != nil {
		return res, err
	}
	payload, c2r, r2c, err := hs.ReadMessage(nil, resp.NoiseMsg2[:])
	if err != nil || c2r == nil || r2c == nil {
		return res, ErrHandshake
	}
	if len(payload) != msg2PayloadLen {
		return res, errPayload
	}
	copy(res.RelayCID[:], payload[:8])
	copy(res.ResetToken[:], payload[8:])
	res.Keys = TrafficKeys{Send: c2r.UnsafeKey(), Recv: r2c.UnsafeKey()}
	return res, nil
}

// RelayConfig configures the responder side of a handshake.
type RelayConfig struct {
	Static StaticKey
	Rand   io.Reader // ephemeral key source; nil uses crypto/rand
}

// RelayResult is the outcome of answering a HANDSHAKE_INIT.
type RelayResult struct {
	Keys         TrafficKeys
	ClientStatic []byte
	Resp         wire.HandshakeResp
}

// RespondHandshake processes a HANDSHAKE_INIT and produces the
// HANDSHAKE_RESP carrying the relay's CID and reset token for path 0.
// Callers must check the cookie (§9.3) before calling this, because it
// performs Diffie-Hellman operations.
func RespondHandshake(cfg RelayConfig, init *wire.HandshakeInit, relayCID wire.CID, resetToken wire.Token) (RelayResult, error) {
	var res RelayResult
	r := cfg.Rand
	if r == nil {
		r = rand.Reader
	}
	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   cipherSuite,
		Random:        r,
		Pattern:       noise.HandshakeIK,
		Initiator:     false,
		Prologue:      init.Prologue(),
		StaticKeypair: cfg.Static,
	})
	if err != nil {
		return res, err
	}
	payload, _, _, err := hs.ReadMessage(nil, init.NoiseMsg1[:])
	if err != nil {
		return res, ErrHandshake
	}
	if len(payload) != 0 {
		return res, errPayload
	}
	msg2Payload := append(relayCID[:], resetToken[:]...)
	msg2, c2r, r2c, err := hs.WriteMessage(nil, msg2Payload)
	if err != nil {
		return res, err
	}
	if len(msg2) != wire.NoiseMsg2Len || c2r == nil || r2c == nil {
		return res, ErrHandshake
	}
	res.Resp.DestCID = init.SenderCID
	copy(res.Resp.NoiseMsg2[:], msg2)
	res.Keys = TrafficKeys{Send: r2c.UnsafeKey(), Recv: c2r.UnsafeKey()}
	res.ClientStatic = hs.PeerStatic()
	return res, nil
}
