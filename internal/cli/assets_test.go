package cli_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/output"
)

func TestCLIOptInAssetsFinalPageScopeAndPrivacy(t *testing.T) {
	for _, setting := range []string{"default", "false", "true"} {
		for _, format := range []string{"terminal", "json"} {
			t.Run(setting+"/"+format, func(t *testing.T) {
				var mu sync.Mutex
				var requests []string
				other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					t.Error("off-origin asset requested")
				}))
				defer other.Close()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					requests = append(requests, r.RequestURI)
					mu.Unlock()
					if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
						t.Errorf("unexpected request: %s %#v", r.Method, r.Header)
					}
					if r.URL.Path != "/start" && r.URL.Path != "/page" && r.Referer() != "" {
						t.Errorf("asset sent referrer: %q", r.Referer())
					}
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Location", "/page?private-page=1")
						w.WriteHeader(302)
						fmt.Fprint(w, `<script src="/hop-only"></script>`)
					case "/page":
						w.Header().Set("Server", "nginx")
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Set-Cookie", "private-cookie=secret")
						w.WriteHeader(403) // Valid error-page findings survive optional failures.
						fmt.Fprintf(w, `<script src="/a.js?private-asset=1"></script><script src="/a.js?private-asset=1#duplicate"></script>
<link rel="stylesheet" href="/b.css?private-css=1"><script src="%s/no.js"></script>
<script src="/redirect?private-redirect=1"></script><script src="/html?private-html=1"></script>
<script src="/missing?private-missing=1"></script><script src="/sixth"></script><a href="/linked">link</a>`, other.URL)
					case "/a.js":
						w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
						w.Header().Set("Content-Encoding", "gzip")
						w.Header().Set("X-Powered-By", "Express")
						gz := gzip.NewWriter(w)
						fmt.Fprint(gz, `/* private-body <meta name="generator" content="WordPress"> */ import "/nested.js";`)
						if err := gz.Close(); err != nil {
							t.Error(err)
						}
					case "/b.css":
						w.Header().Set("Content-Type", "text/css")
						w.Header().Set("Server", "Apache")
						fmt.Fprint(w, `@import "/nested.css"; /*# sourceMappingURL=/source.map */`)
					case "/redirect":
						w.Header().Set("Location", "/redirect-destination?private-location=1")
						w.WriteHeader(302)
					case "/html":
						w.Header().Set("Content-Type", "text/html")
						fmt.Fprint(w, "private-body")
					case "/missing":
						w.WriteHeader(404)
						fmt.Fprint(w, "private-body")
					default:
						t.Errorf("unexpected request: %s", r.URL)
						http.NotFound(w, r)
					}
				}))
				defer server.Close()
				args := []string{"--redact-query", "--no-color", "--allow-http-downgrade"}
				if setting != "default" {
					args = append(args, "--assets="+setting)
				}
				if format == "json" {
					args = append(args, "--json")
				}
				var stdout, stderr bytes.Buffer
				code := cli.Run(append(args, server.URL+"/start?private-start=1"), &stdout, &stderr, "dev")
				if code != 0 || stderr.Len() != 0 {
					t.Fatalf("code=%d stderr=%s", code, &stderr)
				}
				wantRequests := []string{"/start?private-start=1", "/page?private-page=1"}
				if setting == "true" {
					wantRequests = append(wantRequests, "/a.js?private-asset=1", "/b.css?private-css=1", "/redirect?private-redirect=1", "/html?private-html=1", "/missing?private-missing=1")
				}
				mu.Lock()
				gotRequests := append([]string(nil), requests...)
				mu.Unlock()
				if !reflect.DeepEqual(gotRequests, wantRequests) {
					t.Errorf("requests=%v want=%v", gotRequests, wantRequests)
				}
				if strings.Contains(stdout.String(), "private-") || strings.Contains(stdout.String(), "Express") || strings.Contains(stdout.String(), "Apache") || strings.Contains(stdout.String(), "WordPress") {
					t.Fatalf("leaked data or asset-based detection: %s", &stdout)
				}
				if format == "json" {
					var report output.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					if len(report.Findings) != 1 || report.Findings[0].ID != "nginx" || report.ResponseScope != "http_error_response" {
						t.Fatalf("findings/scope=%+v", report)
					}
					if setting == "true" {
						a := report.Assets
						if a == nil || a.Status != "incomplete" || a.Mode != "collection_only" || a.Attempted != 5 || a.Collected != 2 || !a.Truncated || a.Duplicates != 1 || a.SkippedDeclarations != 1 || len(a.Items) != 5 {
							t.Fatalf("assets=%+v", a)
						}
						for i, want := range []string{"", "", "redirect_not_allowed", "unsuitable_content_type", "unsuccessful_status"} {
							if a.Items[i].Reason != want || !strings.HasSuffix(a.Items[i].URL, "?[redacted]") {
								t.Errorf("item=%+v want reason=%q", a.Items[i], want)
							}
						}
					} else if report.Assets != nil || strings.Contains(stdout.String(), `"assets"`) {
						t.Error("default output gained asset fields")
					}
				} else if !strings.Contains(stdout.String(), "nginx [web server]") || strings.Contains(stdout.String(), "Assets:") != (setting == "true") {
					t.Fatalf("output=%s", &stdout)
				}
			})
		}
	}
}

func TestCLIAssetsArgumentsAndPageFailure(t *testing.T) {
	for _, args := range [][]string{{"--techs", "--assets"}, {"--techs", "--assets=false"}, {"--assets=maybe"}} {
		var stdout, stderr bytes.Buffer
		if code := cli.Run(args, &stdout, &stderr, "dev"); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Errorf("args=%v exit=%d stdout=%q stderr=%q", args, code, &stdout, &stderr)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<script src="/a.js"></script>`)
	}))
	defer server.Close()
	for _, format := range []string{"--json", "--no-color"} {
		var stdout, stderr bytes.Buffer
		if code := cli.Run([]string{"--assets", format, "--max-body=1", server.URL}, &stdout, &stderr, "dev"); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "body limit") {
			t.Errorf("exit=%d stdout=%q stderr=%q", code, &stdout, &stderr)
		}
	}
}

func TestCLIAssetTimeoutPreservesPage(t *testing.T) {
	var mu sync.Mutex
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		switch r.URL.Path {
		case "/":
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("Server", "nginx")
			fmt.Fprint(w, `<script src="/slow"></script><script src="/never"></script>`)
		case "/slow":
			w.Header().Set("Content-Type", "text/javascript")
			fmt.Fprint(w, "partial")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
		default:
			t.Error("requested after timeout")
		}
	}))
	defer server.Close()
	var stdout, stderr bytes.Buffer
	code := cli.Run([]string{"--assets", "--json", "--timeout=500ms", server.URL}, &stdout, &stderr, "dev")
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, &stderr)
	}
	var report output.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Assets == nil || report.Assets.Status != "incomplete" || report.Assets.Attempted != 1 || len(report.Assets.Items) != 2 || report.Assets.Items[0].Reason != "timeout" || report.Assets.Items[1].Status != "skipped" || len(report.Findings) != 1 || report.Findings[0].ID != "nginx" {
		t.Fatalf("report=%+v assets=%+v", report, report.Assets)
	}
	mu.Lock()
	defer mu.Unlock()
	if !reflect.DeepEqual(paths, []string{"/", "/slow"}) {
		t.Errorf("paths=%v", paths)
	}
}
