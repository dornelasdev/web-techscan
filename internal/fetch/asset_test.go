package fetch

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestFetchAssetResponsePolicyAndCleanup(t *testing.T) {
	for _, tc := range []struct {
		name     string
		status   int
		types    []string
		location string
		wantErr  error
	}{
		{"javascript", 200, []string{"application/javascript; charset=utf-8"}, "", nil},
		{"case-insensitive-mime", 200, []string{"TEXT/JAVASCRIPT"}, "", nil},
		{"redirect", 302, []string{"text/javascript"}, "/private-target?secret", ErrAssetRedirect},
		{"cross-origin-redirect", 307, []string{"text/javascript"}, "http://other.invalid/private", ErrAssetRedirect},
		{"downgrade", 301, []string{"text/javascript"}, "http://fixture.invalid/private", ErrAssetRedirect},
		{"not-modified", 304, []string{"text/javascript"}, "", ErrAssetStatus},
		{"error", 403, []string{"text/javascript"}, "", ErrAssetStatus},
		{"partial", 206, []string{"text/javascript"}, "", ErrAssetStatus},
		{"html", 200, []string{"text/html"}, "", ErrAssetMediaType},
		{"css-is-not-js", 200, []string{"text/css"}, "", ErrAssetMediaType},
		{"missing-type", 200, nil, "", ErrAssetMediaType},
		{"repeated-type", 200, []string{"text/javascript", "text/javascript"}, "", ErrAssetMediaType},
		{"bad-type", 200, []string{"private-type; broken"}, "", ErrAssetMediaType},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := DefaultOptions()
			options.AllowHTTPDowngrade = true // Still cannot relax asset policy.
			c, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseIdleConnections()
			calls, reads, closed := 0, 0, false
			reader := strings.NewReader("code")
			c.transport.RegisterProtocol("https", lifecycleTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				if calls > 1 {
					t.Fatal("asset redirect followed")
				}
				if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Accept-Encoding") != "gzip" || r.Header.Get("Cookie") != "" || r.Referer() != "" || r.Header.Get("Authorization") != "" {
					t.Errorf("unexpected request: %#v", r.Header)
				}
				headers := http.Header{"Content-Type": tc.types}
				if tc.location != "" {
					headers.Set("Location", tc.location)
				}
				return &http.Response{StatusCode: tc.status, Header: headers, Request: r, Body: lifecycleBody{
					read:  func(p []byte) (int, error) { reads++; return reader.Read(p) },
					close: func() error { closed = true; return nil },
				}}, nil
			}))
			got, err := c.FetchAsset(context.Background(), "https://fixture.invalid/file?private-query", AssetOptions{32, 64, []string{"text/javascript", "application/javascript"}})
			if !errors.Is(err, tc.wantErr) || got.StatusCode != tc.status || !closed || calls != 1 {
				t.Fatalf("result=%+v err=%v closed=%t calls=%d", got, err, closed, calls)
			}
			if tc.wantErr != nil {
				if got.Body != nil || reads != 0 || got.Usage != (BodyUsage{}) || strings.Contains(err.Error(), "private-") {
					t.Fatalf("rejected asset read or leaked data: %+v err=%v reads=%d", got, err, reads)
				}
			} else if string(got.Body) != "code" || got.Usage != (BodyUsage{Decoded: 4, Encoded: 4}) {
				t.Fatalf("bad body/accounting: %+v", got)
			}
		})
	}
}

func TestMeasuredAssetBodiesIncludeFailedReads(t *testing.T) {
	gz := gzipBytes(t, "code")
	corrupt := bytes.Clone(gz)
	corrupt[len(corrupt)-8] ^= 0xff
	for _, tc := range []struct {
		name, encoding             string
		wire                       []byte
		decodedLimit, encodedLimit int64
		wantErr                    error
		decoded                    int64
	}{
		{"plain-exact", "", []byte("code"), 4, 4, nil, 4},
		{"decoded-overflow", "", []byte("long-code"), 4, 64, ErrBodyLimit, 5},
		{"encoded-overflow", "", []byte("long-code"), 64, 4, ErrEncodedBodyLimit, 4},
		{"gzip-exact", "gzip", gz, 4, int64(len(gz)), nil, 4},
		{"gzip-checksum", "gzip", corrupt, 64, 64, nil, 4},
		{"gzip-header-limit", "gzip", gz, 64, 3, ErrEncodedBodyLimit, 0},
		{"empty-members", "gzip", bytes.Repeat(gzipBytes(t, ""), 10), 64, 40, ErrEncodedBodyLimit, 0},
		{"unsupported", "private-encoding", []byte("code"), 64, 64, ErrContentEncoding, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, err := New(DefaultOptions())
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseIdleConnections()
			reader, closed := bytes.NewReader(tc.wire), false
			c.transport.RegisterProtocol("http", lifecycleTransport(func(r *http.Request) (*http.Response, error) {
				headers := http.Header{"Content-Type": {"text/css"}}
				if tc.encoding != "" {
					headers.Set("Content-Encoding", tc.encoding)
				}
				return &http.Response{StatusCode: 200, Header: headers, Request: r, Body: lifecycleBody{read: reader.Read, close: func() error { closed = true; return nil }}}, nil
			}))
			got, err := c.FetchAsset(context.Background(), "http://fixture.invalid/asset", AssetOptions{tc.decodedLimit, tc.encodedLimit, []string{"text/css"}})
			if tc.name == "gzip-checksum" {
				if err == nil {
					t.Fatal("corrupt gzip accepted")
				}
			} else if !errors.Is(err, tc.wantErr) {
				t.Fatalf("err=%v want=%v", err, tc.wantErr)
			}
			if !closed || got.Usage.Decoded != tc.decoded || got.Usage.Encoded != int64(len(tc.wire)-reader.Len()) || got.Usage.Encoded > tc.encodedLimit+1 {
				t.Fatalf("bad usage/cleanup: %+v closed=%t unread=%d", got.Usage, closed, reader.Len())
			}
			if err != nil && got.Body != nil {
				t.Fatal("partial body exposed")
			}
		})
	}
}

func TestAssetUsesParentDeadlineAndAccountsCancellation(t *testing.T) {
	c, err := New(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	closed, reads := false, 0
	requests := 0
	c.transport.RegisterProtocol("http", lifecycleTransport(func(r *http.Request) (*http.Response, error) {
		requests++
		got, ok := r.Context().Deadline()
		if !ok || !got.Equal(deadline) {
			t.Error("deadline reset")
		}
		if r.URL.Path == "/page" {
			return &http.Response{StatusCode: 200, Header: make(http.Header), Request: r, Body: http.NoBody}, nil
		}
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"text/css"}}, Request: r, Body: lifecycleBody{
			read: func(p []byte) (int, error) {
				reads++
				if reads == 1 {
					return copy(p, "part"), nil
				}
				cancel()
				return 0, ctx.Err()
			}, close: func() error { closed = true; return nil },
		}}, nil
	}))
	if _, err := c.Fetch(ctx, "http://fixture.invalid/page"); err != nil {
		t.Fatal(err)
	}
	got, err := c.FetchAsset(ctx, "http://fixture.invalid/asset", AssetOptions{64, 64, []string{"text/css"}})
	if !errors.Is(err, context.Canceled) || got.Body != nil || got.Usage != (BodyUsage{4, 4}) || !closed || requests != 2 {
		t.Fatalf("result=%+v err=%v closed=%t", got, err, closed)
	}
}

func TestAssetOptionAndRequestFailures(t *testing.T) {
	c, err := New(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	calls := 0
	c.transport.RegisterProtocol("http", lifecycleTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return nil, errors.New("private-query and raw server data")
	}))
	for _, options := range []AssetOptions{{}, {0, 1, []string{"text/css"}}, {1, 0, []string{"text/css"}}, {math.MaxInt64, 1, []string{"text/css"}}, {1, math.MaxInt64, []string{"text/css"}}, {1, 1, nil}} {
		if _, err := c.FetchAsset(context.Background(), "http://fixture.invalid/", options); err == nil {
			t.Fatal("invalid options accepted")
		}
	}
	if calls != 0 {
		t.Fatal("invalid options made a request")
	}
	got, err := c.FetchAsset(context.Background(), "http://fixture.invalid/?private-query", AssetOptions{64, 64, []string{"text/css"}})
	if err == nil || strings.Contains(err.Error(), "private-") || got.Body != nil || got.Usage != (BodyUsage{}) || calls != 1 {
		t.Fatalf("got=%+v err=%v calls=%d", got, err, calls)
	}
}

func TestFetchAssetPreservesTLSVerification(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("untrusted asset reached HTTP handler")
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	options := DefaultOptions()
	options.AllowHTTPDowngrade = true
	c, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	got, err := c.FetchAsset(context.Background(), server.URL+"/?private-query", AssetOptions{64, 64, []string{"text/css"}})
	var certificate *tls.CertificateVerificationError
	if !errors.As(err, &certificate) || got.Body != nil || got.Usage != (BodyUsage{}) || strings.Contains(err.Error(), "private-") {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}
