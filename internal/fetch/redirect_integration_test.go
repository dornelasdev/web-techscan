package fetch_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"webscan/internal/fetch"
)

func TestRedirectErrorsDoNotPrintDestinations(t *testing.T) {
	for _, tc := range []struct {
		name, location, reason string
		limit                  int
	}{
		{"credentials", "http://private-user:private-password@HOST/target?token=private-query", "embedded credentials are not supported", 5},
		{"malformed", "/%zz?token=private-query", "network error or invalid HTTP response", 5},
		{"malformed-credentials", "http://private-user:private-password@HOST/%zz", "network error or invalid HTTP response", 5},
		{"scheme", "ftp://HOST/target?token=private-query", "include an http:// or https:// scheme", 5},
		{"limit", "/target?token=private-query", "redirect limit exceeded (maximum 0)", 0},
		{"limit-with-credentials", "http://private-user:private-password@HOST/target", "redirect limit exceeded (maximum 0)", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests.Add(1)
				w.Header().Set("Location", strings.ReplaceAll(tc.location, "HOST", r.Host))
				w.WriteHeader(http.StatusFound)
			}))
			defer server.Close()
			options := fetch.DefaultOptions()
			options.MaxRedirects = tc.limit
			got, err := newClient(t, options).Fetch(context.Background(), server.URL+"/start?token=private-start")
			if err == nil || got != nil {
				t.Fatalf("snapshot=%v err=%v; expected failure without a partial snapshot", got, err)
			}
			if !strings.Contains(err.Error(), tc.reason) || errors.Is(err, fetch.ErrInvalidURL) {
				t.Errorf("unexpected error: %v", err)
			}
			if errors.Is(err, fetch.ErrRedirectLimit) != (tc.limit == 0) {
				t.Errorf("lost redirect classification: %v", err)
			}
			for _, raw := range []string{"private-user", "private-password", "private-query", "private-start", server.URL, "%zz"} {
				if strings.Contains(err.Error(), raw) {
					t.Errorf("diagnostic contains %q", raw)
				}
			}
			if requests.Load() != 1 {
				t.Errorf("rejected redirect was followed: %d requests", requests.Load())
			}
		})
	}
}

func TestRedirectRefererUsesImmediateOrigin(t *testing.T) {
	type request struct{ path, referer string }
	var mu sync.Mutex
	var got []request
	var firstURL, secondURL string
	handler := func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, request{r.URL.Path, r.Referer()})
		firstOrigin, secondOrigin := firstURL, secondURL
		mu.Unlock()
		if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			t.Errorf("unexpected request method or headers: %s %v", r.Method, r.Header)
		}
		http.SetCookie(w, &http.Cookie{Name: "hop", Value: "private-cookie"})
		switch r.URL.Path {
		case "/start":
			http.Redirect(w, r, "/same?token=private-first#discard", http.StatusMovedPermanently)
		case "/same":
			http.Redirect(w, r, secondOrigin+"/entry?token=private-second", http.StatusFound)
		case "/entry":
			http.Redirect(w, r, "/finish", http.StatusSeeOther)
		case "/finish":
			http.Redirect(w, r, firstOrigin+"/done", http.StatusTemporaryRedirect)
		case "/done":
			fmt.Fprint(w, "done")
		default:
			http.NotFound(w, r)
		}
	}
	first := httptest.NewServer(http.HandlerFunc(handler))
	defer first.Close()
	second := httptest.NewServer(http.HandlerFunc(handler))
	defer second.Close()
	mu.Lock()
	firstURL, secondURL = first.URL, second.URL
	mu.Unlock()
	snapshot, err := newClient(t, fetch.DefaultOptions()).Fetch(context.Background(), firstURL+"/start?token=private-start#discard")
	if err != nil {
		t.Fatal(err)
	}
	want := []request{
		{"/start", ""}, {"/same", firstURL + "/start?token=private-start"},
		{"/entry", ""}, {"/finish", secondURL + "/entry?token=private-second"}, {"/done", ""},
	}
	mu.Lock()
	visited := append([]request(nil), got...)
	mu.Unlock()
	if !reflect.DeepEqual(visited, want) {
		t.Errorf("requests=%+v want=%+v", visited, want)
	}
	if snapshot.FinalURL != firstURL+"/done" || len(snapshot.Redirects) != 4 || string(snapshot.Body) != "done" {
		t.Errorf("unexpected final snapshot: %+v", snapshot)
	}
}
