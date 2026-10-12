package crypto

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/rand/v2"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/laneshetron/arc/internal/wire"
)

type fixtures struct {
	HandshakeIK struct {
		ClientStaticPrivate    string `json:"client_static_private_hex"`
		ClientStaticPublic     string `json:"client_static_public_hex"`
		ClientEphemeralPrivate string `json:"client_ephemeral_private_hex"`
		RelayStaticPrivate     string `json:"relay_static_private_hex"`
		RelayStaticPublic      string `json:"relay_static_public_hex"`
		RelayEphemeralPrivate  string `json:"relay_ephemeral_private_hex"`
		Msg2Payload            string `json:"msg2_payload_hex"`
		HandshakeInit          string `json:"handshake_init_hex"`
		HandshakeResp          string `json:"handshake_resp_hex"`
		ClientToRelayKey       string `json:"client_to_relay_key_hex"`
		RelayToClientKey       string `json:"relay_to_client_key_hex"`
	} `json:"handshake_ik"`
	DataAEAD struct {
		Key       string `json:"key_hex"`
		PathID    uint32 `json:"path_id"`
		Nonce     string `json:"nonce_hex"`
		Plaintext string `json:"plaintext_hex"`
		Packet    string `json:"packet_hex"`
	} `json:"data_aead"`
	Rekey struct {
		Epoch0 string `json:"epoch0_key_hex"`
		Epoch1 string `json:"epoch1_key_hex"`
		Epoch2 string `json:"epoch2_key_hex"`
	} `json:"rekey"`
	Cookie struct {
		Secret    string `json:"cookie_secret_hex"`
		SrcIP     string `json:"src_ip"`
		SrcPort   uint16 `json:"src_port"`
		SenderCID string `json:"sender_cid_hex"`
		Cookie    string `json:"cookie_hex"`
	} `json:"cookie"`
	ResetToken struct {
		Secret string `json:"reset_secret_hex"`
		CID    string `json:"cid_hex"`
		Token  string `json:"reset_token_hex"`
	} `json:"reset_token"`
}

func loadFixtures(t *testing.T) *fixtures {
	t.Helper()
	data, err := os.ReadFile("../../spec/ARC-v1-Wire-Fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f fixtures
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	return &f
}

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func key32(t *testing.T, s string) (k [32]byte) {
	t.Helper()
	copy(k[:], unhex(t, s))
	return k
}

func cid(t *testing.T, s string) (c wire.CID) {
	t.Helper()
	copy(c[:], unhex(t, s))
	return c
}

func staticKey(t *testing.T, priv string) StaticKey {
	t.Helper()
	k, err := GenerateStaticKey(bytes.NewReader(unhex(t, priv)))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// TestHandshakeVector checks flynn/noise against the vector produced by the
// independent Python noiseprotocol implementation.
func TestHandshakeVector(t *testing.T) {
	f := loadFixtures(t).HandshakeIK
	clientStatic := staticKey(t, f.ClientStaticPrivate)
	relayStatic := staticKey(t, f.RelayStaticPrivate)
	if hex.EncodeToString(relayStatic.Public) != f.RelayStaticPublic {
		t.Fatalf("relay public key = %x", relayStatic.Public)
	}

	wantInit, err := wire.ParseHandshakeInit(unhex(t, f.HandshakeInit))
	if err != nil {
		t.Fatal(err)
	}
	ch, err := NewClientHandshake(ClientConfig{
		Static:      clientStatic,
		RelayPublic: relayStatic.Public,
		SenderCID:   wantInit.SenderCID,
		Rand:        bytes.NewReader(unhex(t, f.ClientEphemeralPrivate)),
	})
	if err != nil {
		t.Fatal(err)
	}
	init := ch.Init(nil)
	if got := init.Append(nil); hex.EncodeToString(got) != f.HandshakeInit {
		t.Fatalf("HANDSHAKE_INIT =\n%x\nwant\n%s", got, f.HandshakeInit)
	}

	payload := unhex(t, f.Msg2Payload)
	relayCID, token := wire.CID(payload[:8]), wire.Token(payload[8:])
	rr, err := RespondHandshake(RelayConfig{
		Static: relayStatic,
		Rand:   bytes.NewReader(unhex(t, f.RelayEphemeralPrivate)),
	}, &init, relayCID, token)
	if err != nil {
		t.Fatal(err)
	}
	if got := rr.Resp.Append(nil); hex.EncodeToString(got) != f.HandshakeResp {
		t.Fatalf("HANDSHAKE_RESP =\n%x\nwant\n%s", got, f.HandshakeResp)
	}
	if hex.EncodeToString(rr.ClientStatic) != f.ClientStaticPublic {
		t.Errorf("relay learned client static %x", rr.ClientStatic)
	}

	cr, err := ch.Finish(&rr.Resp)
	if err != nil {
		t.Fatal(err)
	}
	if cr.RelayCID != relayCID || cr.ResetToken != token {
		t.Errorf("client result = %+v", cr)
	}
	c2r, r2c := key32(t, f.ClientToRelayKey), key32(t, f.RelayToClientKey)
	if cr.Keys != (TrafficKeys{Send: c2r, Recv: r2c}) || rr.Keys != (TrafficKeys{Send: r2c, Recv: c2r}) {
		t.Errorf("traffic keys do not match the vector")
	}
}

func TestHandshakeWrongRelayKey(t *testing.T) {
	client, _ := GenerateStaticKey(nil)
	relay, _ := GenerateStaticKey(nil)
	impostor, _ := GenerateStaticKey(nil)

	// Client pinned the real relay; an impostor cannot read message 1.
	ch, err := NewClientHandshake(ClientConfig{Static: client, RelayPublic: relay.Public})
	if err != nil {
		t.Fatal(err)
	}
	init := ch.Init(nil)
	if _, err := RespondHandshake(RelayConfig{Static: impostor}, &init, wire.CID{}, wire.Token{}); err == nil {
		t.Fatal("impostor relay completed the handshake")
	}

	// Client pinned the wrong key; the real relay cannot read message 1 either.
	ch, _ = NewClientHandshake(ClientConfig{Static: client, RelayPublic: impostor.Public})
	init = ch.Init(nil)
	if _, err := RespondHandshake(RelayConfig{Static: relay}, &init, wire.CID{}, wire.Token{}); err == nil {
		t.Fatal("relay accepted a handshake pinned to another key")
	}
}

func TestHandshakeSurvivesForgedResponse(t *testing.T) {
	client, _ := GenerateStaticKey(nil)
	relay, _ := GenerateStaticKey(nil)
	sender := wire.CID{1, 2, 3, 4, 5, 6, 7, 8}
	ch, _ := NewClientHandshake(ClientConfig{Static: client, RelayPublic: relay.Public, SenderCID: sender})
	init := ch.Init(nil)

	forged := wire.HandshakeResp{DestCID: sender}
	forged.NoiseMsg2[0] = 1
	if _, err := ch.Finish(&forged); err == nil {
		t.Fatal("forged response accepted")
	}
	wrongDest := wire.HandshakeResp{DestCID: wire.CID{9}}
	if _, err := ch.Finish(&wrongDest); err == nil {
		t.Fatal("response for another CID accepted")
	}

	rr, err := RespondHandshake(RelayConfig{Static: relay}, &init, wire.CID{7}, wire.Token{8})
	if err != nil {
		t.Fatal(err)
	}
	cr, err := ch.Finish(&rr.Resp)
	if err != nil {
		t.Fatalf("genuine response after forgery: %v", err)
	}
	if cr.Keys.Send != rr.Keys.Recv || cr.Keys.Recv != rr.Keys.Send {
		t.Error("keys disagree")
	}
}

func TestInitIsStableAcrossRetransmissionsAndCookies(t *testing.T) {
	client, _ := GenerateStaticKey(nil)
	relay, _ := GenerateStaticKey(nil)
	ch, _ := NewClientHandshake(ClientConfig{Static: client, RelayPublic: relay.Public})
	a, b := ch.Init(nil), ch.Init(nil)
	cookie := [wire.CookieLen]byte{1}
	c := ch.Init(&cookie)
	if a != b || a.NoiseMsg1 != c.NoiseMsg1 || c.Cookie != cookie {
		t.Fatal("INIT not stable")
	}
	if _, err := RespondHandshake(RelayConfig{Static: relay}, &c, wire.CID{}, wire.Token{}); err != nil {
		t.Fatalf("INIT with cookie: %v", err)
	}
}

func TestDataAEADVector(t *testing.T) {
	f := loadFixtures(t).DataAEAD
	packet := unhex(t, f.Packet)
	h, aad, ct, err := wire.ParseData(packet)
	if err != nil {
		t.Fatal(err)
	}
	if n := Nonce(f.PathID, h.PacketNumber); hex.EncodeToString(n[:]) != f.Nonce {
		t.Errorf("nonce = %x", n)
	}
	a := NewAEAD(key32(t, f.Key))
	if got := a.SealData(nil, h, f.PathID, unhex(t, f.Plaintext)); !bytes.Equal(got, packet) {
		t.Errorf("sealed =\n%x\nwant\n%x", got, packet)
	}
	pt, err := a.OpenData(nil, h, aad, f.PathID, ct)
	if err != nil || hex.EncodeToString(pt) != f.Plaintext {
		t.Fatalf("open: %x, %v", pt, err)
	}
	if _, err := a.OpenData(nil, h, aad, f.PathID+1, ct); !errors.Is(err, ErrAuth) {
		t.Error("opened under the wrong path_id")
	}
	for i := range wire.DataHeaderLen {
		mutated := bytes.Clone(packet)
		mutated[i] ^= 0x01
		mh, maad, mct, err := wire.ParseData(mutated)
		if err != nil {
			continue // mutated type byte
		}
		if _, err := a.OpenData(nil, mh, maad, f.PathID, mct); err == nil {
			t.Errorf("header byte %d not authenticated", i)
		}
	}
}

func TestRekeyVector(t *testing.T) {
	f := loadFixtures(t).Rekey
	k1 := Rekey(key32(t, f.Epoch0))
	if hex.EncodeToString(k1[:]) != f.Epoch1 {
		t.Errorf("epoch 1 key = %x", k1)
	}
	if k2 := Rekey(k1); hex.EncodeToString(k2[:]) != f.Epoch2 {
		t.Errorf("epoch 2 key = %x", k2)
	}
}

func TestCookieAndResetVectors(t *testing.T) {
	f := loadFixtures(t)
	src := netip.AddrPortFrom(netip.MustParseAddr(f.Cookie.SrcIP), f.Cookie.SrcPort)
	c := ComputeCookie(key32(t, f.Cookie.Secret), src, cid(t, f.Cookie.SenderCID))
	if hex.EncodeToString(c[:]) != f.Cookie.Cookie {
		t.Errorf("cookie = %x", c)
	}
	mapped := netip.AddrPortFrom(netip.AddrFrom16(src.Addr().As16()), src.Port())
	if ComputeCookie(key32(t, f.Cookie.Secret), mapped, cid(t, f.Cookie.SenderCID)) != c {
		t.Error("IPv4-mapped address produced a different cookie")
	}
	tok := ResetToken(key32(t, f.ResetToken.Secret), cid(t, f.ResetToken.CID))
	if hex.EncodeToString(tok[:]) != f.ResetToken.Token {
		t.Errorf("reset token = %x", tok)
	}
}

func TestCookieRotation(t *testing.T) {
	t0 := time.Unix(1000, 0)
	g := NewCookieGenerator(nil, t0)
	src := netip.MustParseAddrPort("192.0.2.1:4433")
	sender := wire.CID{1}
	c := g.Make(t0, src, sender)

	if !g.Verify(t0.Add(time.Second), src, sender, c) {
		t.Error("fresh cookie rejected")
	}
	if g.Verify(t0, netip.MustParseAddrPort("192.0.2.1:4434"), sender, c) {
		t.Error("cookie accepted from another port")
	}
	if g.Verify(t0, src, wire.CID{2}, c) {
		t.Error("cookie accepted for another CID")
	}
	if !g.Verify(t0.Add(CookieRotation+time.Second), src, sender, c) {
		t.Error("previous-secret cookie rejected after one rotation")
	}
	if g.Verify(t0.Add(2*CookieRotation+time.Second), src, sender, c) {
		t.Error("cookie accepted after two rotations")
	}

	g = NewCookieGenerator(nil, t0)
	c = g.Make(t0, src, sender)
	if g.Verify(t0.Add(10*CookieRotation), src, sender, c) {
		t.Error("cookie accepted after a long idle period")
	}
}

func TestReplayWindowModel(t *testing.T) {
	rng := rand.New(rand.NewPCG(1, 2))
	var w ReplayWindow
	seen := map[uint64]bool{}
	var highest uint64
	started := false
	for range 200000 {
		var pn uint64
		switch r := rng.IntN(100); {
		case r < 60 && started: // near the top: reordering and duplicates
			pn = highest + 64 - uint64(rng.IntN(256))
			if pn > highest+64 { // underflow guard for small highest
				pn = uint64(rng.IntN(64))
			}
		case r < 95:
			pn = highest + uint64(rng.IntN(3))
		default: // occasional large jumps and very old packets
			if rng.IntN(2) == 0 {
				pn = highest + uint64(rng.IntN(20000))
			} else if highest > ReplayWindowSize {
				pn = highest - ReplayWindowSize - uint64(rng.IntN(100))
			}
		}
		want := !seen[pn] && (!started || pn > highest || highest-pn < ReplayWindowSize)
		if got := w.Check(pn); got != want {
			t.Fatalf("Check(%d) = %v, want %v (highest %d)", pn, got, want, highest)
		}
		if got := w.Record(pn); got != want {
			t.Fatalf("Record(%d) = %v, want %v", pn, got, want)
		}
		if want {
			seen[pn] = true
			if !started || pn > highest {
				highest, started = pn, true
			}
		}
	}
}

func TestReplayWindowBasics(t *testing.T) {
	var w ReplayWindow
	for _, pn := range []uint64{5, 0, 7, 6} {
		if !w.Record(pn) {
			t.Fatalf("first Record(%d) failed", pn)
		}
	}
	if w.Check(5) || w.Record(0) {
		t.Error("duplicate accepted")
	}
	if !w.Record(5 + ReplayWindowSize) {
		t.Fatal("jump rejected")
	}
	if w.Check(5) || w.Check(6) {
		t.Error("packet older than the window accepted")
	}
	if !w.Check(7 + 64) {
		t.Error("unseen packet inside the window rejected")
	}
}

func TestEpochs(t *testing.T) {
	now := time.Unix(1000, 0)
	k0 := [32]byte{1}
	send, recv := NewSendKeys(k0, now), NewRecvKeys(k0)

	seal := func(pn uint64) (wire.DataHeader, []byte, []byte) {
		pkt := send.Seal(nil, wire.DataHeader{PacketNumber: pn}, 3, []byte{0x0a, 0, 0})
		h, aad, ct, err := wire.ParseData(pkt)
		if err != nil {
			t.Fatal(err)
		}
		return h, aad, ct
	}
	open := func(h wire.DataHeader, aad, ct []byte, at time.Time) (uint64, error) {
		_, e, err := recv.Open(nil, h, aad, 3, ct, at)
		return e, err
	}

	if send.RekeyDue(now.Add(RekeyAfterTime - time.Second)) {
		t.Error("rekey due early")
	}
	if !send.RekeyDue(now.Add(RekeyAfterTime)) {
		t.Error("rekey not due after RekeyAfterTime")
	}

	h0, a0, c0 := seal(0) // epoch 0, delivered late
	send.Advance(now)
	h1, a1, c1 := seal(1) // epoch 1

	if e, err := open(h1, a1, c1, now); err != nil || e != 1 || recv.Epoch() != 1 {
		t.Fatalf("epoch 1 packet: epoch %d, err %v", e, err)
	}
	if e, err := open(h0, a0, c0, now.Add(KeyOverlap-time.Second)); err != nil || e != 0 {
		t.Fatalf("reordered epoch 0 packet: epoch %d, err %v", e, err)
	}
	if _, err := open(h0, a0, c0, now.Add(KeyOverlap)); !errors.Is(err, ErrEpoch) {
		t.Errorf("epoch 0 packet after overlap: %v", err)
	}

	// Two epochs ahead cannot be resolved.
	send.Advance(now)
	send.Advance(now)
	h3, a3, c3 := seal(2)
	if _, err := open(h3, a3, c3, now); !errors.Is(err, ErrEpoch) {
		t.Errorf("epoch 3 at receiver epoch 1: %v", err)
	}

	// A forged next-epoch packet must not advance the receiver.
	forged := wire.DataHeader{EpochLow: 2, PacketNumber: 9}
	fpkt := append(forged.Append(nil), make([]byte, 19)...)
	fh, fa, fc, _ := wire.ParseData(fpkt)
	if _, err := open(fh, fa, fc, now); !errors.Is(err, ErrAuth) || recv.Epoch() != 1 {
		t.Errorf("forged next-epoch packet: err %v, epoch %d", err, recv.Epoch())
	}
}

func TestEpochLowWraps(t *testing.T) {
	now := time.Unix(1000, 0)
	k := [32]byte{2}
	send, recv := NewSendKeys(k, now), NewRecvKeys(k)
	for pn := range uint64(300) {
		pkt := send.Seal(nil, wire.DataHeader{PacketNumber: pn}, 1, []byte{0x0a, 0, 0})
		h, aad, ct, _ := wire.ParseData(pkt)
		if _, e, err := recv.Open(nil, h, aad, 1, ct, now); err != nil || e != send.Epoch() {
			t.Fatalf("pn %d epoch %d: got epoch %d, err %v", pn, send.Epoch(), e, err)
		}
		send.Advance(now)
	}
}

func TestSealOpenDoNotAllocate(t *testing.T) {
	a := NewAEAD([32]byte{1})
	pt := make([]byte, 1300)
	dst := make([]byte, 0, 2048)
	pkt := a.SealData(make([]byte, 0, 2048), wire.DataHeader{PacketNumber: 1}, 0, pt)
	h, aad, ct, _ := wire.ParseData(pkt)
	out := make([]byte, 0, 2048)
	allocs := testing.AllocsPerRun(100, func() {
		a.SealData(dst, wire.DataHeader{PacketNumber: 2}, 0, pt)
		if _, err := a.OpenData(out, h, aad, 0, ct); err != nil {
			t.Fatal(err)
		}
	})
	if allocs != 0 {
		t.Errorf("seal+open allocate %v times per packet", allocs)
	}
}
