package fetch_test

import (
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"webscan/internal/fetch"
)

func newClient(t *testing.T, options fetch.Options) *fetch.Client {
	t.Helper()
	c, err := fetch.New(options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.CloseIdleConnections)
	return c
}

func TestSnapshotKeepsFinalResponseSeparate(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if r.Method != http.MethodGet || r.UserAgent() != "webscan" {
			t.Errorf("unexpected request: %s, User-Agent %q", r.Method, r.UserAgent())
		}
		if r.URL.Path == "/start" {
			w.Header().Set("Server", "redirect-server")
			http.SetCookie(w, &http.Cookie{Name: "redirect_only", Value: "secret"})
			http.Redirect(w, r, "/final", http.StatusFound)
			return
		}
		if r.URL.Path != "/final" {
			t.Errorf("unexpected asset request: %s", r.URL.Path)
		}
		if r.Header.Get("Cookie") != "" {
			t.Error("redirect cookies should not be replayed")
		}
		w.Header().Set("Server", "final-server")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "secret-one"})
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "secret-two", Path: "/other"})
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `<script src="/asset.js"></script>`)
	}))
	defer server.Close()

	c := newClient(t, fetch.DefaultOptions())
	snapshot, err := c.Fetch(context.Background(), server.URL+"/start#fragment")
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.OriginalURL != server.URL+"/start" || snapshot.FinalURL != server.URL+"/final" {
		t.Errorf("unexpected URLs: %+v", snapshot)
	}
	if snapshot.StatusCode != 404 || snapshot.Headers.Get("Server") != "final-server" {
		t.Errorf("expected final response metadata: %+v", snapshot)
	}
	if snapshot.Headers.Get("Set-Cookie") != "" || !reflect.DeepEqual(snapshot.CookieNames, []string{"session"}) {
		t.Errorf("unexpected cookie retention: headers=%v, names=%v", snapshot.Headers, snapshot.CookieNames)
	}
	wantRedirects := []fetch.Redirect{{FromURL: server.URL + "/start", ToURL: server.URL + "/final", StatusCode: 302}}
	if !reflect.DeepEqual(snapshot.Redirects, wantRedirects) {
		t.Errorf("redirects = %+v, want %+v", snapshot.Redirects, wantRedirects)
	}
	if string(snapshot.Body) != `<script src="/asset.js"></script>` || requests.Load() != 2 {
		t.Errorf("body = %q, requests = %d", snapshot.Body, requests.Load())
	}
	// Reusing the fetcher must not retain a previous call's redirect history.
	second, err := c.Fetch(context.Background(), server.URL+"/final")
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Redirects) != 0 {
		t.Errorf("redirect history leaked between calls: %+v", second.Redirects)
	}
}

func TestRedirectBudget(t *testing.T) {
	for _, limit := range []int{0, 2, 3} {
		t.Run(strconv.Itoa(limit), func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				hop, _ := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
				if hop < 3 {
					http.Redirect(w, r, fmt.Sprintf("/%d", hop+1), http.StatusFound)
					return
				}
				fmt.Fprint(w, "done")
			}))
			defer server.Close()
			options := fetch.DefaultOptions()
			options.MaxRedirects = limit
			snapshot, err := newClient(t, options).Fetch(context.Background(), server.URL+"/0")
			if limit < 3 {
				if !errors.Is(err, fetch.ErrRedirectLimit) || snapshot != nil {
					t.Fatalf("snapshot=%v, error=%v; want redirect limit without partial result", snapshot, err)
				}
			} else if err != nil || len(snapshot.Redirects) != 3 {
				t.Fatalf("snapshot=%v, error=%v; want exactly three redirects", snapshot, err)
			}
			if requests.Load() != int32(limit+1) {
				t.Errorf("requests=%d, want %d", requests.Load(), limit+1)
			}
		})
	}
}

func TestInvalidRedirectIsAnExecutionError(t *testing.T) {
	for _, location := range []string{"ftp://example.com/file", "http://user:secret@example.com/"} {
		t.Run(location, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", location)
				w.WriteHeader(http.StatusFound)
			}))
			defer server.Close()
			_, err := newClient(t, fetch.DefaultOptions()).Fetch(context.Background(), server.URL)
			if err == nil || errors.Is(err, fetch.ErrInvalidURL) {
				t.Errorf("error=%v, want a redirect execution error", err)
			}
		})
	}
}

func TestBodyBudget(t *testing.T) {
	for _, encoding := range []string{"plain", "chunked", "gzip"} {
		for _, size := range []int{32, 33} {
			t.Run(fmt.Sprintf("%s/%d", encoding, size), func(t *testing.T) {
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					body := strings.Repeat("x", size)
					switch encoding {
					case "chunked":
						w.(http.Flusher).Flush()
						fmt.Fprint(w, body)
					case "gzip":
						w.Header().Set("Content-Encoding", "gzip")
						writer := gzip.NewWriter(w)
						fmt.Fprint(writer, body)
						writer.Close()
					default:
						fmt.Fprint(w, body)
					}
				}))
				defer server.Close()
				options := fetch.DefaultOptions()
				options.MaxBodyBytes = 32
				snapshot, err := newClient(t, options).Fetch(context.Background(), server.URL)
				if size > 32 {
					if !errors.Is(err, fetch.ErrBodyLimit) || snapshot != nil {
						t.Fatalf("snapshot=%v, error=%v; want body limit without partial result", snapshot, err)
					}
				} else if err != nil || string(snapshot.Body) != strings.Repeat("x", size) {
					t.Fatalf("snapshot=%v, error=%v; want exact-size body", snapshot, err)
				}
			})
		}
	}
}

func TestTimeoutCoversHeadersAndBody(t *testing.T) {
	for _, flushHeaders := range []bool{false, true} {
		t.Run(fmt.Sprintf("body=%t", flushHeaders), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if flushHeaders {
					w.(http.Flusher).Flush()
				}
				<-r.Context().Done()
			}))
			defer server.Close()
			options := fetch.DefaultOptions()
			options.Timeout = 100 * time.Millisecond
			snapshot, err := newClient(t, options).Fetch(context.Background(), server.URL)
			if !errors.Is(err, context.DeadlineExceeded) || snapshot != nil {
				t.Fatalf("snapshot=%v, error=%v; want deadline exceeded", snapshot, err)
			}
		})
	}
}

func TestCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := newClient(t, fetch.DefaultOptions()).Fetch(ctx, "http://127.0.0.1:1/")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error=%v, want context cancellation", err)
	}
}

func TestTLSVerification(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("request reached a server with an untrusted certificate")
	}))
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.StartTLS()
	defer server.Close()
	_, err := newClient(t, fetch.DefaultOptions()).Fetch(context.Background(), server.URL)
	if err == nil {
		t.Fatal("expected untrusted TLS certificate to be rejected")
	}
}

func TestOversizedHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Large", strings.Repeat("x", (1<<20)+4096))
		fmt.Fprint(w, "small body")
	}))
	defer server.Close()
	snapshot, err := newClient(t, fetch.DefaultOptions()).Fetch(context.Background(), server.URL)
	if err == nil || snapshot != nil {
		t.Fatalf("snapshot=%v, error=%v; want header limit error", snapshot, err)
	}
}

func TestIncompleteBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		fmt.Fprint(w, "short")
	}))
	defer server.Close()
	snapshot, err := newClient(t, fetch.DefaultOptions()).Fetch(context.Background(), server.URL)
	if !errors.Is(err, io.ErrUnexpectedEOF) || snapshot != nil {
		t.Fatalf("snapshot=%v, error=%v; want incomplete body error", snapshot, err)
	}
}

func TestInvalidLimits(t *testing.T) {
	for _, options := range []fetch.Options{
		{Timeout: 0, MaxRedirects: 5, MaxBodyBytes: 1024},
		{Timeout: -time.Second, MaxRedirects: 5, MaxBodyBytes: 1024},
		{Timeout: time.Second, MaxRedirects: -1, MaxBodyBytes: 1024},
		{Timeout: time.Second, MaxBodyBytes: 0},
		{Timeout: time.Second, MaxBodyBytes: -1},
		{Timeout: time.Second, MaxBodyBytes: math.MaxInt64},
	} {
		options.MaxEncodedBodyBytes = fetch.DefaultOptions().MaxEncodedBodyBytes
		if _, err := fetch.New(options); err == nil {
			t.Errorf("accepted invalid limits: %+v", options)
		}
	}
}
