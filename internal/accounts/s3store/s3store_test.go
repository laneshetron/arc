package s3store

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/laneshetron/arc/internal/accounts"
)

// fakeS3 is one bucket's conditional GET and PUT, path-style.
type fakeS3 struct {
	mu      sync.Mutex
	objects map[string][]byte
	// failAfterPut, while positive, makes a PUT apply and then answer 500,
	// as a response lost after S3 took the write; the client retries.
	failAfterPut int
	puts         int
}

func etag(b []byte) string { h := md5.Sum(b); return `"` + hex.EncodeToString(h[:]) + `"` }

func (f *fakeS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	cur, exists := f.objects[r.URL.Path]
	fail := func(code int, s3code string) {
		w.Header().Set("Content-Type", "application/xml")
		w.WriteHeader(code)
		fmt.Fprintf(w, "<Error><Code>%s</Code><Message>%s</Message></Error>", s3code, s3code)
	}
	switch r.Method {
	case http.MethodGet:
		if !exists {
			fail(http.StatusNotFound, "NoSuchKey")
			return
		}
		w.Header().Set("ETag", etag(cur))
		w.Write(cur)
	case http.MethodPut:
		f.puts++
		body, _ := io.ReadAll(r.Body)
		if m := r.Header.Get("If-Match"); m != "" && (!exists || m != etag(cur)) {
			fail(http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		if r.Header.Get("If-None-Match") == "*" && exists {
			fail(http.StatusPreconditionFailed, "PreconditionFailed")
			return
		}
		f.objects[r.URL.Path] = body
		if f.failAfterPut > 0 {
			f.failAfterPut--
			fail(http.StatusInternalServerError, "InternalError")
			return
		}
		w.Header().Set("ETag", etag(body))
	default:
		fail(http.StatusMethodNotAllowed, "MethodNotAllowed")
	}
}

func fakeStore(t *testing.T) (*Store, *fakeS3) {
	t.Helper()
	f := &fakeS3{objects: map[string][]byte{}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	client := s3.New(s3.Options{
		Region:                     "us-east-1",
		BaseEndpoint:               aws.String(srv.URL),
		UsePathStyle:               true,
		Credentials:                credentials.NewStaticCredentialsProvider("AKID", "SECRET", ""),
		RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired,
	})
	return &Store{Client: client, Bucket: "bucket", Key: "accounts"}, f
}

func TestConditionalWrites(t *testing.T) {
	ctx := context.Background()
	s, _ := fakeStore(t)
	if _, _, err := s.Get(ctx); !errors.Is(err, accounts.ErrNotFound) {
		t.Fatalf("empty store: %v", err)
	}
	v1, err := s.Put(ctx, []byte("a"), "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, []byte("b"), ""); !errors.Is(err, accounts.ErrConflict) {
		t.Fatalf("create over an existing object: %v", err)
	}
	v2, err := s.Put(ctx, []byte("b"), v1)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, []byte("c"), v1); !errors.Is(err, accounts.ErrConflict) {
		t.Fatalf("stale If-Match: %v", err)
	}
	if data, v, err := s.Get(ctx); err != nil || string(data) != "b" || v != v2 {
		t.Fatalf("get: %q %s %v", data, v, err)
	}
}

// TestWriterOverS3: the writer's lease and commits over S3, including a
// write whose response is lost, which the client retries and S3 refuses
// (412) because the first attempt applied it.
func TestWriterOverS3(t *testing.T) {
	ctx := context.Background()
	s, f := fakeStore(t)
	w := &accounts.Writer{Store: s, Holder: "a"}
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	f.failAfterPut, f.puts = 1, 0
	f.mu.Unlock()
	if err := w.Commit(ctx, func(st *accounts.State) error { _, err := accounts.AddAccount(st, "x", false, 0); return err }); err != nil {
		t.Fatalf("commit with a lost response: %v", err)
	}
	f.mu.Lock()
	puts := f.puts
	f.mu.Unlock()
	if puts < 2 || !w.Serving() || w.State().AccountByName("x") == nil {
		t.Fatalf("after the retried write: %d puts, serving %v", puts, w.Serving())
	}
	if err := w.Commit(ctx, func(st *accounts.State) error { _, err := accounts.AddAccount(st, "y", false, 0); return err }); err != nil {
		t.Fatalf("next commit: %v", err)
	}
	other := &accounts.Writer{Store: s, Holder: "b"}
	var held *accounts.HeldError
	if err := other.Acquire(ctx); !errors.As(err, &held) {
		t.Fatalf("second writer: %v", err)
	}
	if err := w.Release(ctx); err != nil {
		t.Fatal(err)
	}
	if err := other.Acquire(ctx); err != nil || other.State().AccountByName("y") == nil {
		t.Fatalf("after release: %v", err)
	}
}

// TestRealS3 runs the conditional writes against a real bucket, when
// ARC_S3_TEST_URL names an object (s3://BUCKET/KEY) that may be
// overwritten and deleted.
func TestRealS3(t *testing.T) {
	url := os.Getenv("ARC_S3_TEST_URL")
	if url == "" {
		t.Skip("ARC_S3_TEST_URL not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	s, err := Open(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	del := func() { s.Client.DeleteObject(ctx, &s3.DeleteObjectInput{Bucket: &s.Bucket, Key: &s.Key}) }
	del()
	t.Cleanup(del)
	cache := filepath.Join(t.TempDir(), "cache")
	w := &accounts.Writer{Store: s, Holder: "test", Cache: cache}
	if err := w.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Commit(ctx, func(st *accounts.State) error { _, err := accounts.AddAccount(st, "x", false, 0); return err }); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Put(ctx, []byte("stale"), `"0123"`); !errors.Is(err, accounts.ErrConflict) {
		t.Fatalf("stale If-Match: %v", err)
	}
	if _, err := s.Put(ctx, []byte("exists"), ""); !errors.Is(err, accounts.ErrConflict) {
		t.Fatalf("If-None-Match over an object: %v", err)
	}
	if err := w.Release(ctx); err != nil {
		t.Fatal(err)
	}
}
