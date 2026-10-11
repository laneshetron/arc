// Package keyfile reads and writes the base64 key and secret files used by
// the arc-client and arc-relay commands.
package keyfile

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/laneshetron/arc/internal/crypto"
)

// Encode returns the base64 form of a 32-byte key.
func Encode(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

// Decode32 parses a base64 32-byte value.
func Decode32(s string) ([32]byte, error) {
	var out [32]byte
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(s))
	if err != nil {
		return out, err
	}
	if len(b) != 32 {
		return out, fmt.Errorf("keyfile: want 32 bytes, got %d", len(b))
	}
	copy(out[:], b)
	return out, nil
}

// StaticFromPrivate derives the static key pair for a private key.
func StaticFromPrivate(priv [32]byte) (crypto.StaticKey, error) {
	return crypto.GenerateStaticKey(bytes.NewReader(priv[:]))
}

// LoadStatic reads a base64 private key file.
func LoadStatic(path string) (crypto.StaticKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return crypto.StaticKey{}, err
	}
	priv, err := Decode32(string(b))
	if err != nil {
		return crypto.StaticKey{}, fmt.Errorf("%s: %w", path, err)
	}
	return StaticFromPrivate(priv)
}

// LoadOrCreateSecret reads a base64 32-byte secret, creating the file with
// a random secret (mode 0600) if it does not exist.
func LoadOrCreateSecret(path string) ([32]byte, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		var s [32]byte
		if _, err := rand.Read(s[:]); err != nil {
			return s, err
		}
		return s, os.WriteFile(path, []byte(Encode(s[:])+"\n"), 0o600)
	}
	if err != nil {
		return [32]byte{}, err
	}
	return Decode32(string(b))
}

// ReadLines returns the non-empty, non-comment lines of a file.
func ReadLines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out, nil
}
