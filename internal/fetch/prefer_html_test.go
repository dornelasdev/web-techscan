package fetch

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

func TestHTMLPreferenceAcrossPageRedirects(t *testing.T) {
	const first = "https://one.invalid/start?token=private-query"
	const same = "https://one.invalid/final?token=private-query"
	const other = "https://two.invalid/final?token=private-query"
	const plain = "http://one.invalid/final?token=private-query"
	if DefaultOptions().PreferHTML {
		t.Fatal("HTML preference must remain opt-in")
	}
	for _, prefer := range []bool{false, true} {
		for _, tc := range []struct {
			name      string
			chain     []string
			limit     int
			allowDown bool
			wantErr   error
			wantCalls int
		}{
			{"direct", []string{first}, 5, false, nil, 1},
			{"relative", []string{first, same}, 5, false, nil, 2},
			{"cross-origin", []string{first, other}, 5, false, nil, 2},
			{"return-to-origin", []string{first, other, same}, 5, false, nil, 3},
			{"upgrade", []string{plain, same}, 5, false, nil, 2},
			{"downgrade-blocked", []string{first, plain}, 5, false, ErrHTTPSDowngrade, 1},
			{"downgrade-allowed", []string{first, plain}, 5, true, nil, 2},
			{"redirects-disabled", []string{first, same}, 0, false, ErrRedirectLimit, 1},
			{"redirect-budget", []string{first, other, same}, 1, false, ErrRedirectLimit, 2},
			{"exact-redirect-budget", []string{first, other, same}, 2, false, nil, 3},
		} {
			t.Run(tc.name+"/prefer="+strconv.FormatBool(prefer), func(t *testing.T) {
				options := DefaultOptions()
				options.PreferHTML, options.AllowHTTPDowngrade, options.MaxRedirects = prefer, tc.allowDown, tc.limit
				c, err := New(options)
				if err != nil {
					t.Fatal(err)
				}
				defer c.CloseIdleConnections()
				var visited []string
				transport := lifecycleTransport(func(r *http.Request) (*http.Response, error) {
					i := len(visited)
					visited = append(visited, r.URL.String())
					if i >= tc.wantCalls {
						t.Fatalf("unexpected extra request: %s", r.URL)
					}
					wantAccept := ""
					wantAcceptFields := 0
					if prefer {
						wantAccept = "text/html, application/xhtml+xml;q=0.9, */*;q=0.8"
						wantAcceptFields = 1
					}
					if r.Header.Get("Accept") != wantAccept || len(r.Header.Values("Accept")) != wantAcceptFields || r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Accept-Encoding") != "gzip" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
						t.Errorf("unexpected request policy: %s %v", r.Method, r.Header)
					}
					wantReferer := ""
					if i > 0 {
						previous, err := url.Parse(tc.chain[i-1])
						if err != nil {
							t.Fatal(err)
						}
						if previous.Scheme == r.URL.Scheme && previous.Host == r.URL.Host {
							wantReferer = previous.String()
						}
					}
					if r.Referer() != wantReferer {
						t.Errorf("Referer=%q want=%q", r.Referer(), wantReferer)
					}
					resp := &http.Response{StatusCode: 404, Header: make(http.Header), Body: io.NopCloser(strings.NewReader("final body")), Request: r}
					resp.Header.Set("Content-Type", "text/html")
					if i+1 < len(tc.chain) {
						resp.StatusCode = 302
						resp.Header.Set("Set-Cookie", "session=private-cookie")
						resp.Header.Set("Server", "redirect-only")
						location := tc.chain[i+1]
						next, _ := url.Parse(location)
						if next.Scheme == r.URL.Scheme && next.Host == r.URL.Host {
							location = next.RequestURI() // Exercise relative redirects too.
						}
						resp.Header.Set("Location", location)
					}
					return resp, nil
				})
				// No sockets: exercise http.Client's normal redirect handling with
				// deterministic responses on both schemes, not TLS verification.
				c.transport.RegisterProtocol("http", transport)
				c.transport.RegisterProtocol("https", transport)
				snapshot, err := c.Fetch(context.Background(), tc.chain[0])
				if !errors.Is(err, tc.wantErr) {
					t.Fatalf("error=%v want=%v", err, tc.wantErr)
				}
				if !reflect.DeepEqual(visited, tc.chain[:tc.wantCalls]) {
					t.Errorf("requests=%v want=%v", visited, tc.chain[:tc.wantCalls])
				}
				if tc.wantErr != nil {
					if snapshot != nil || strings.Contains(err.Error(), "private-") || strings.Contains(err.Error(), ".invalid") {
						t.Errorf("partial snapshot or unsafe error: %+v %v", snapshot, err)
					}
					return
				}
				if snapshot == nil || snapshot.StatusCode != 404 || snapshot.OriginalURL != tc.chain[0] || snapshot.FinalURL != tc.chain[len(tc.chain)-1] || string(snapshot.Body) != "final body" || len(snapshot.Redirects) != len(tc.chain)-1 || len(snapshot.CookieNames) != 0 || snapshot.Headers.Get("Server") != "" {
					t.Fatalf("unexpected snapshot: %+v", snapshot)
				}
			})
		}
	}
}

func TestHTMLPreferencePreservesBodyPolicies(t *testing.T) {
	const html = "<h1>Returned error</h1>"
	for _, tc := range []struct {
		name, encoding string
		wire           []byte
		decoded, raw   int64
		wantErr        error
	}{
		{"plain", "", []byte(html), 64, 128, nil},
		{"gzip", "gzip", gzipBytes(t, html), 64, 128, nil},
		{"decoded-limit", "", []byte(html), 4, 128, ErrBodyLimit},
		{"encoded-limit", "", []byte(html), 64, 4, ErrEncodedBodyLimit},
		{"unsupported-encoding", "private-encoding", []byte(html), 64, 128, ErrContentEncoding},
	} {
		t.Run(tc.name, func(t *testing.T) {
			options := DefaultOptions()
			options.PreferHTML, options.MaxBodyBytes, options.MaxEncodedBodyBytes = true, tc.decoded, tc.raw
			c, err := New(options)
			if err != nil {
				t.Fatal(err)
			}
			defer c.CloseIdleConnections()
			calls, closed := 0, false
			reader := bytes.NewReader(tc.wire)
			c.transport.RegisterProtocol("http", lifecycleTransport(func(r *http.Request) (*http.Response, error) {
				calls++
				headers := make(http.Header)
				if tc.encoding != "" {
					headers.Set("Content-Encoding", tc.encoding)
				}
				return &http.Response{StatusCode: 404, Header: headers, Request: r, Body: lifecycleBody{
					read: reader.Read,
					close: func() error {
						closed = true
						return nil
					},
				}}, nil
			}))
			// The request preference must not introduce a retry after any failure.
			snapshot, err := c.Fetch(context.Background(), "http://fixture.invalid/page?private-query")
			if !errors.Is(err, tc.wantErr) || calls != 1 || !closed {
				t.Fatalf("error=%v want=%v calls=%d closed=%t", err, tc.wantErr, calls, closed)
			}
			if tc.wantErr != nil {
				if snapshot != nil {
					t.Errorf("partial snapshot returned: %+v", snapshot)
				}
			} else if snapshot == nil || string(snapshot.Body) != html {
				t.Errorf("unexpected snapshot: %+v", snapshot)
			}
		})
	}
}
