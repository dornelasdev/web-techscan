package fetch

import (
	"context"
	"errors"
	"io"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"
)

type lifecycleTransport func(*http.Request) (*http.Response, error)

func (f lifecycleTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type lifecycleBody struct {
	read  func([]byte) (int, error)
	close func() error
}

func (b lifecycleBody) Read(p []byte) (int, error) { return b.read(p) }
func (b lifecycleBody) Close() error               { return b.close() }

func TestOneDeadlineAcrossRedirectsAndBody(t *testing.T) {
	options := DefaultOptions()
	options.Timeout = 200 * time.Millisecond
	c, err := New(options)
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	var firstDeadline time.Time
	var paths []string
	closed := false
	c.transport.RegisterProtocol("http", lifecycleTransport(func(r *http.Request) (*http.Response, error) {
		paths = append(paths, r.URL.Path)
		deadline, ok := r.Context().Deadline()
		if !ok {
			t.Error("request has no deadline")
		}
		if firstDeadline.IsZero() {
			firstDeadline = deadline
		} else if !deadline.Equal(firstDeadline) {
			t.Error("timeout budget restarted on redirect")
		}
		resp := &http.Response{StatusCode: 302, Header: make(http.Header), Body: http.NoBody, Request: r}
		switch r.URL.Path {
		case "/start":
			resp.Header.Set("Location", "/middle")
		case "/middle":
			resp.Header.Set("Location", "/final")
		case "/final":
			resp.StatusCode = 200
			resp.Body = lifecycleBody{
				read:  func([]byte) (int, error) { <-r.Context().Done(); return 0, r.Context().Err() },
				close: func() error { closed = true; return nil },
			}
		default:
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		return resp, nil
	}))
	snapshot, err := c.Fetch(context.Background(), "http://fixture.invalid/start")
	if !errors.Is(err, context.DeadlineExceeded) || snapshot != nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("snapshot=%v err=%v", snapshot, err)
	}
	if !reflect.DeepEqual(paths, []string{"/start", "/middle", "/final"}) || !closed {
		t.Errorf("paths=%v body closed=%t", paths, closed)
	}
}

func TestCancelDuringBodyRead(t *testing.T) {
	c, err := New(DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	defer c.CloseIdleConnections()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := false
	reads := 0
	c.transport.RegisterProtocol("http", lifecycleTransport(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Request: r, Body: lifecycleBody{
			read: func(p []byte) (int, error) {
				reads++
				if reads == 1 {
					return copy(p, "partial"), nil
				}
				cancel() // Deterministic cancellation after a partial body was consumed.
				<-r.Context().Done()
				return 0, r.Context().Err()
			},
			close: func() error { closed = true; return nil },
		}}, nil
	}))
	snapshot, err := c.Fetch(ctx, "http://fixture.invalid/page")
	if !errors.Is(err, context.Canceled) || snapshot != nil || !closed || reads != 2 {
		t.Fatalf("snapshot=%v err=%v closed=%t reads=%d", snapshot, err, closed, reads)
	}
}

func TestBodyFailureClosesResponse(t *testing.T) {
	for _, encoding := range []string{"private-unsupported", "gzip"} {
		c, err := New(DefaultOptions())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.CloseIdleConnections)
		closed := false
		reader := strings.NewReader("not a valid gzip stream")
		c.transport.RegisterProtocol("http", lifecycleTransport(func(r *http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": {encoding}}, Request: r, Body: lifecycleBody{read: reader.Read, close: func() error { closed = true; return nil }}}, nil
		}))
		got, err := c.Fetch(context.Background(), "http://fixture.invalid/")
		if err == nil || got != nil || !closed {
			t.Fatalf("snapshot=%v err=%v closed=%t", got, err, closed)
		}
	}
}

var _ io.ReadCloser = lifecycleBody{}
