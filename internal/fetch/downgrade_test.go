package fetch

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"
)

func TestRedirectDowngradePolicy(t *testing.T) {
	const plain = "http://fixture.invalid/final?token=private-final"
	const secure = "https://fixture.invalid/start?token=private-start"
	for _, tc := range []struct {
		name     string
		hops     []string
		allow    bool
		limit    int
		wantErr  error
		requests int
	}{
		{"direct-http", []string{plain}, false, 5, nil, 1},
		{"direct-https", []string{secure}, false, 5, nil, 1},
		{"http-http", []string{plain, "http://other.invalid/final"}, false, 5, nil, 2},
		{"http-https", []string{plain, secure}, false, 5, nil, 2},
		{"https-https", []string{secure, "https://other.invalid/final"}, false, 5, nil, 2},
		{"same-host-downgrade", []string{secure, plain}, false, 5, ErrHTTPSDowngrade, 1},
		{"other-host-downgrade", []string{secure, "http://other.invalid/final"}, false, 5, ErrHTTPSDowngrade, 1},
		{"mixed-case-schemes", []string{"HTTPS://fixture.invalid/", "HTTP://fixture.invalid/final"}, false, 5, ErrHTTPSDowngrade, 1},
		{"ports-do-not-change-policy", []string{"https://fixture.invalid:80/", "http://fixture.invalid:443/"}, false, 5, ErrHTTPSDowngrade, 1},
		{"upgrade-then-downgrade", []string{plain, secure, plain}, false, 5, ErrHTTPSDowngrade, 2},
		{"opt-in", []string{secure, plain}, true, 5, nil, 2},
		{"opt-in-chain", []string{plain, secure, plain, secure, plain}, true, 5, nil, 5},
		{"zero-budget-still-blocks", []string{secure, plain}, true, 0, ErrRedirectLimit, 1},
		{"budget-still-bounded", []string{secure, plain, secure}, true, 1, ErrRedirectLimit, 2},
	} {
		for _, status := range []int{301, 302, 303, 307, 308} {
			t.Run(fmt.Sprintf("%s/status=%d", tc.name, status), func(t *testing.T) {
				options := DefaultOptions()
				options.AllowHTTPDowngrade = tc.allow
				options.MaxRedirects = tc.limit
				c, err := New(options)
				if err != nil {
					t.Fatal(err)
				}
				defer c.CloseIdleConnections()
				var visited []string
				closed := 0
				transport := lifecycleTransport(func(r *http.Request) (*http.Response, error) {
					i := len(visited)
					visited = append(visited, r.URL.String())
					if i >= len(tc.hops) {
						return nil, errors.New("unexpected extra request")
					}
					if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Cookie") != "" {
						t.Errorf("request policy changed: %s %v", r.Method, r.Header)
					}
					if i > 0 {
						prior, _ := ParseURL(tc.hops[i-1])
						if !SameOrigin(prior, r.URL) && r.Referer() != "" {
							t.Error("cross-origin redirect sent Referer")
						}
					}
					resp := &http.Response{StatusCode: 200, Request: r, Header: make(http.Header),
						Body: lifecycleBody{read: strings.NewReader("page").Read, close: func() error { closed++; return nil }}}
					if i+1 < len(tc.hops) {
						resp.StatusCode = status
						resp.Header.Set("Location", tc.hops[i+1])
						resp.Header.Set("Set-Cookie", "hop=private-cookie")
					}
					return resp, nil
				})
				// Exercise http.Client redirect handling without DNS or sockets.
				c.transport.RegisterProtocol("http", transport)
				c.transport.RegisterProtocol("https", transport)
				snapshot, err := c.Fetch(context.Background(), tc.hops[0])
				if tc.wantErr != nil {
					if !errors.Is(err, tc.wantErr) || errors.Is(err, ErrInvalidURL) || snapshot != nil {
						t.Fatalf("snapshot=%v err=%v want=%v", snapshot, err, tc.wantErr)
					}
					var cause *url.Error
					if !errors.As(err, &cause) {
						t.Error("request error cause was lost")
					}
					for _, raw := range []string{"private-", "fixture.invalid", "other.invalid"} {
						if strings.Contains(err.Error(), raw) {
							t.Errorf("unsafe error: %q", err.Error())
						}
					}
				} else {
					if err != nil || snapshot == nil {
						t.Fatalf("snapshot=%v err=%v", snapshot, err)
					}
					if snapshot.FinalURL != visited[len(visited)-1] || string(snapshot.Body) != "page" || len(snapshot.Redirects) != len(tc.hops)-1 {
						t.Errorf("unexpected snapshot: %+v", snapshot)
					}
					for i, hop := range snapshot.Redirects {
						if hop.FromURL != visited[i] || hop.ToURL != visited[i+1] || hop.StatusCode != status {
							t.Errorf("incorrect hop metadata: %+v", hop)
						}
					}
				}
				var want []string
				for _, raw := range tc.hops[:tc.requests] {
					u, parseErr := ParseURL(raw)
					if parseErr != nil {
						t.Fatal(parseErr)
					}
					want = append(want, u.String())
				}
				if !reflect.DeepEqual(visited, want) || closed != len(visited) {
					t.Errorf("visited=%q want=%q bodies closed=%d", visited, want, closed)
				}
			})
		}
	}
}
