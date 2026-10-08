package fetch_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync"
	"testing"

	"webscan/internal/fetch"
)

func TestEncodingIsTakenOnlyFromFinalResponse(t *testing.T) {
	var wire bytes.Buffer
	gz := gzip.NewWriter(&wire)
	if _, err := fmt.Fprint(gz, "decoded page"); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.Header.Get("Accept-Encoding") != "gzip" {
			t.Error("gzip negotiation missing on a hop")
		}
		switch r.URL.Path {
		case "/start":
			w.Header().Set("Content-Encoding", "private-unsupported")
			w.Header().Set("Location", "/final")
			w.WriteHeader(http.StatusFound)
			fmt.Fprint(w, "ignored redirect body")
		case "/final":
			w.Header().Set("Content-Encoding", "gzip")
			w.Header().Set("Content-Length", fmt.Sprint(wire.Len()))
			w.Write(wire.Bytes())
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	snapshot, err := newClient(t, fetch.DefaultOptions()).Fetch(context.Background(), server.URL+"/start")
	if err != nil {
		t.Fatal(err)
	}
	if string(snapshot.Body) != "decoded page" || snapshot.Headers.Get("Content-Encoding") != "" || snapshot.Headers.Get("Content-Length") != "" || len(snapshot.Redirects) != 1 {
		t.Errorf("unexpected snapshot: %+v", snapshot)
	}
	mu.Lock()
	got := append([]string(nil), paths...)
	mu.Unlock()
	if !reflect.DeepEqual(got, []string{"/start", "/final"}) {
		t.Errorf("unexpected requests: %v", got)
	}
}
