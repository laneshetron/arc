package keyfile

import (
	"bytes"
	"path/filepath"
	"testing"

	"github.com/laneshetron/arc/internal/crypto"
)

func TestStaticRoundTrip(t *testing.T) {
	k, _ := crypto.GenerateStaticKey(nil)
	priv, err := Decode32(Encode(k.Private) + "\n")
	if err != nil {
		t.Fatal(err)
	}
	again, err := StaticFromPrivate(priv)
	if err != nil || !bytes.Equal(again.Public, k.Public) {
		t.Fatalf("public key mismatch: %v", err)
	}
	if _, err := Decode32(Encode([]byte("short"))); err == nil {
		t.Error("accepted a short key")
	}
}

func TestLoadOrCreateSecretPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	a, err := LoadOrCreateSecret(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadOrCreateSecret(path)
	if err != nil || a != b || a == ([32]byte{}) {
		t.Fatalf("secret not persisted: %v", err)
	}
}
