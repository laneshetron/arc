// Package s3store keeps the relay's accounts in one S3 object
// (self-service-accounts.md §3.2): reads are GetObject, and every write
// is a PutObject conditioned on the ETag the writer last read (If-Match),
// or on the object not existing yet (If-None-Match: *). S3 makes those
// writes atomic, so it is the commit point and the writer lease's fence.
package s3store

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	smithyhttp "github.com/aws/smithy-go/transport/http"

	"github.com/laneshetron/arc/internal/accounts"
)

// maxObject bounds what Get reads: the accounts file stays well under
// 1 MiB (§3.2).
const maxObject = 4 << 20

// Store is an accounts.Store in the object Key of Bucket.
type Store struct {
	Client *s3.Client
	Bucket string
	Key    string
}

// Open opens the store an s3://BUCKET/KEY URL names, with the default
// AWS configuration: credentials from the environment or the instance
// role, and the region from AWS_REGION.
func Open(ctx context.Context, url string) (*Store, error) {
	bucket, key, ok := strings.Cut(strings.TrimPrefix(url, "s3://"), "/")
	if !strings.HasPrefix(url, "s3://") || !ok || bucket == "" || key == "" {
		return nil, fmt.Errorf("%q: want s3://BUCKET/KEY", url)
	}
	cfg, err := config.LoadDefaultConfig(ctx)
	if err != nil {
		return nil, fmt.Errorf("AWS configuration: %w", err)
	}
	if cfg.Region == "" {
		return nil, errors.New("AWS region not set (AWS_REGION)")
	}
	return &Store{Client: s3.NewFromConfig(cfg), Bucket: bucket, Key: key}, nil
}

func (s *Store) Get(ctx context.Context) ([]byte, string, error) {
	out, err := s.Client.GetObject(ctx, &s3.GetObjectInput{Bucket: &s.Bucket, Key: &s.Key})
	if err != nil {
		if status(err) == http.StatusNotFound {
			// Without s3:ListBucket, a missing object is a 403 instead,
			// which stays an error: the relay must not seed over it.
			return nil, "", accounts.ErrNotFound
		}
		return nil, "", fmt.Errorf("s3://%s/%s: %w", s.Bucket, s.Key, err)
	}
	defer out.Body.Close()
	data, err := io.ReadAll(io.LimitReader(out.Body, maxObject+1))
	if err != nil {
		return nil, "", fmt.Errorf("s3://%s/%s: %w", s.Bucket, s.Key, err)
	}
	if len(data) > maxObject {
		return nil, "", fmt.Errorf("s3://%s/%s: larger than %d bytes", s.Bucket, s.Key, maxObject)
	}
	return data, aws.ToString(out.ETag), nil
}

func (s *Store) Put(ctx context.Context, data []byte, ifMatch string) (string, error) {
	in := &s3.PutObjectInput{Bucket: &s.Bucket, Key: &s.Key, Body: bytes.NewReader(data),
		ContentType: aws.String("text/plain; charset=utf-8")}
	if ifMatch != "" {
		in.IfMatch = aws.String(ifMatch)
	} else {
		in.IfNoneMatch = aws.String("*")
	}
	out, err := s.Client.PutObject(ctx, in)
	if err != nil {
		// 412: the object is not at ifMatch (or exists, for If-None-Match).
		// 409: another conditional write to it was in flight. Either way,
		// another writer may have committed. A retry of this very write
		// that S3 had already applied also fails 412; the writer tells
		// that apart by reading the object back.
		if c := status(err); c == http.StatusPreconditionFailed || c == http.StatusConflict {
			return "", fmt.Errorf("%w: %v", accounts.ErrConflict, err)
		}
		return "", fmt.Errorf("s3://%s/%s: %w", s.Bucket, s.Key, err)
	}
	if out.ETag == nil {
		return "", fmt.Errorf("s3://%s/%s: no ETag in the response", s.Bucket, s.Key)
	}
	return *out.ETag, nil
}

// status returns the HTTP status of an S3 error, or 0.
func status(err error) int {
	var re *smithyhttp.ResponseError
	if errors.As(err, &re) {
		return re.HTTPStatusCode()
	}
	var ae smithy.APIError
	if errors.As(err, &ae) {
		switch ae.ErrorCode() {
		case "NoSuchKey":
			return http.StatusNotFound
		case "PreconditionFailed":
			return http.StatusPreconditionFailed
		case "ConditionalRequestConflict":
			return http.StatusConflict
		}
	}
	return 0
}
