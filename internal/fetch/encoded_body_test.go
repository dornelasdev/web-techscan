package fetch

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"
	"testing"
)

func TestEncodedBodyBudget(t *testing.T) {
	single := gzipBytes(t, "page")
	empty := gzipBytes(t, "")
	members := append(append([]byte(nil), empty...), single...)
	var padded bytes.Buffer
	w := gzip.NewWriter(&padded)
	w.Extra = bytes.Repeat([]byte("x"), 512)
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name     string
		encoding string
		wire     []byte
		limit    int64
		want     string
		wantErr  error
	}{
		{"gzip-below-limit", "gzip", single, int64(len(single) + 1), "page", nil},
		{"gzip-exact-limit", "gzip", single, int64(len(single)), "page", nil},
		{"gzip-one-over", "gzip", single, int64(len(single) - 1), "", ErrEncodedBodyLimit},
		{"gzip-header-limit", "gzip", single, 3, "", ErrEncodedBodyLimit},
		{"gzip-extra-header-limit", "gzip", padded.Bytes(), 64, "", ErrEncodedBodyLimit},
		{"empty-exact-limit", "gzip", empty, int64(len(empty)), "", nil},
		{"members-exact-limit", "gzip", members, int64(len(members)), "page", nil},
		{"complete-member-is-not-eof", "gzip", members, int64(len(empty)), "", ErrEncodedBodyLimit},
		{"empty-members-exhaust-budget", "gzip", bytes.Repeat(empty, 1000), int64(len(empty) * 3), "", ErrEncodedBodyLimit},
		{"trailing-byte-is-not-eof", "gzip", append(append([]byte(nil), single...), 'x'), int64(len(single)), "", ErrEncodedBodyLimit},
		{"truncated-at-budget", "gzip", single[:len(single)-1], int64(len(single) - 1), "", io.ErrUnexpectedEOF},
		{"identity-exact", "identity", []byte("page"), 4, "page", nil},
		{"identity-one-over", "identity", []byte("page!"), 4, "", ErrEncodedBodyLimit},
		{"plain-one-over", "", []byte("page!"), 4, "", ErrEncodedBodyLimit},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Actual reads decide the limit; Content-Length is not trusted as a
			// substitute. Include unknown and misleading metadata here.
			for _, length := range []int64{-1, 0, 1, int64(len(tc.wire)), math.MaxInt64} {
				raw := bytes.NewReader(tc.wire)
				resp := &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: length, Body: io.NopCloser(raw)}
				if tc.encoding != "" {
					resp.Header.Set("Content-Encoding", tc.encoding)
				}
				body, err := readBody(resp, 1024, tc.limit)
				if tc.wantErr != nil {
					if !errors.Is(err, tc.wantErr) || body != nil {
						t.Fatalf("length=%d body=%q err=%v want=%v", length, body, err, tc.wantErr)
					}
				} else if err != nil || string(body) != tc.want {
					t.Fatalf("length=%d body=%q err=%v want=%q", length, body, err, tc.want)
				}
				if consumed := int64(len(tc.wire) - raw.Len()); consumed > tc.limit+1 {
					t.Errorf("read %d encoded bytes with budget %d", consumed, tc.limit)
				}
			}
		})
	}
}

func TestEncodedReaderBoundaryErrors(t *testing.T) {
	for _, cause := range []error{io.EOF, context.Canceled, context.DeadlineExceeded, io.ErrUnexpectedEOF} {
		t.Run(cause.Error(), func(t *testing.T) {
			calls := 0
			source := lifecycleBody{read: func(p []byte) (int, error) {
				calls++
				if calls == 1 {
					return copy(p, "x"), nil
				}
				return 0, cause
			}}
			r := &encodedBodyReader{reader: source, remaining: 1}
			body, err := io.ReadAll(r)
			if cause == io.EOF {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(safeBodyError(err), cause) {
				t.Fatalf("lost cause: %v", err)
			}
			if string(body) != "x" || calls != 2 {
				t.Fatalf("body=%q calls=%d", body, calls)
			}
		})
	}
	// Maximum positive int64 is supported without adding one to the budget.
	r := &encodedBodyReader{reader: strings.NewReader("x"), remaining: math.MaxInt64}
	if body, err := io.ReadAll(r); err != nil || string(body) != "x" {
		t.Fatalf("body=%q err=%v", body, err)
	}
	// Overflow probes must not repeatedly consume bytes, or return overflow as EOF.
	source := strings.NewReader("xyz")
	r = &encodedBodyReader{reader: source, remaining: 1}
	if _, err := io.ReadAll(r); !errors.Is(err, ErrEncodedBodyLimit) {
		t.Fatal(err)
	}
	if n, err := r.Read(make([]byte, 4)); n != 0 || !errors.Is(err, ErrEncodedBodyLimit) || source.Len() != 1 {
		t.Fatalf("n=%d err=%v remaining source=%d", n, err, source.Len())
	}
}

func TestEncodedLimitClosesBodyWithoutSnapshot(t *testing.T) {
	options := DefaultOptions()
	empty := gzipBytes(t, "")
	options.MaxEncodedBodyBytes = int64(len(empty))
	c, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	closed := false
	reader := bytes.NewReader(bytes.Repeat(empty, 100))
	c.transport.RegisterProtocol("http", lifecycleTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {"gzip"}}, Request: r,
			Body: lifecycleBody{read: reader.Read, close: func() error { closed = true; return nil }}}, nil
	}))
	snapshot, err := c.Fetch(context.Background(), "http://fixture.invalid/?private-query")
	if !errors.Is(err, ErrEncodedBodyLimit) || snapshot != nil || !closed {
		t.Fatalf("snapshot=%v err=%v closed=%t", snapshot, err, closed)
	}
	if strings.Contains(err.Error(), "private-query") || !strings.Contains(err.Error(), ErrEncodedBodyLimit.Error()) {
		t.Fatalf("unexpected diagnostic: %v", err)
	}
}

func TestEncodedLimitOptions(t *testing.T) {
	for _, limit := range []int64{-1, 0, 1, math.MaxInt64} {
		options := DefaultOptions()
		options.MaxEncodedBodyBytes = limit
		c, err := New(options)
		if limit <= 0 {
			if err == nil || !strings.Contains(err.Error(), "max-encoded-body must be positive") {
				t.Fatalf("limit=%d err=%v", limit, err)
			}
		} else {
			if err != nil {
				t.Fatal(err)
			}
			c.CloseIdleConnections()
		}
	}
}
