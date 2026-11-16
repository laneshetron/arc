package accounts

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

var (
	// ErrNotFound: the store holds no accounts object yet.
	ErrNotFound = errors.New("accounts: store is empty")
	// ErrConflict: a conditional write found another version than the
	// one it was conditioned on, so another writer has committed.
	ErrConflict = errors.New("accounts: store changed underneath (another writer)")
)

// A Store is the commit point (§3.2): one object, read whole, replaced
// whole by conditional writes. Implementations must make Put atomic: it
// succeeds only if the object's version is still ifMatch ("" meaning it
// must not exist yet), and then the object is data.
type Store interface {
	Get(ctx context.Context) (data []byte, version string, err error)
	Put(ctx context.Context, data []byte, ifMatch string) (version string, err error)
}

// FileStore is a Store in one local file, for a relay whose accounts
// need not survive its host, and for tests. Writers on the same host are
// serialized by a lock on a separate file; versions are content hashes.
type FileStore struct{ Path string }

func (f FileStore) Get(context.Context) ([]byte, string, error) {
	data, err := os.ReadFile(f.Path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, "", ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	return data, version(data), nil
}

func (f FileStore) Put(_ context.Context, data []byte, ifMatch string) (string, error) {
	unlock, err := lockFile(f.Path + ".lock")
	if err != nil {
		return "", err
	}
	defer unlock()
	cur, err := os.ReadFile(f.Path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		if ifMatch != "" {
			return "", ErrConflict
		}
	case err != nil:
		return "", err
	case version(cur) != ifMatch:
		return "", ErrConflict
	}
	if err := WriteFileAtomic(f.Path, data); err != nil {
		return "", err
	}
	return version(data), nil
}

func version(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:16])
}

// WriteFileAtomic replaces path with data: write a temporary file, sync
// it, rename it over path, and sync the directory.
func WriteFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// lockFile takes an exclusive lock on path, creating it, and returns its
// release. The lock file is never renamed, so every holder locks the same
// inode.
func lockFile(path string) (func(), error) {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		return nil, fmt.Errorf("lock %s: %w", path, err)
	}
	return func() { f.Close() }, nil
}

func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
