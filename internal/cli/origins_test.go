package cli_test

import (
	"bytes"
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

func TestCLIExternalOriginDiscoveryIsOptInAndDoesNotFetch(t *testing.T) {
	for _, setting := range []string{"default", "false", "true"} {
		for _, format := range []string{"plain", "color", "json"} {
			for _, failAsset := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/fail=%t", setting, format, failAsset), func(t *testing.T) {
					external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						t.Error("external origin contacted")
						w.WriteHeader(http.StatusInternalServerError)
					}))
					defer external.Close()
					hopOnly := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						t.Error("redirect/inert/preload origin contacted")
						w.WriteHeader(http.StatusInternalServerError)
					}))
					defer hopOnly.Close()
					var mu sync.Mutex
					var visited []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						visited = append(visited, r.URL.Path)
						mu.Unlock()
						switch r.URL.Path {
						case "/start":
							w.Header().Set("Location", "/page")
							w.WriteHeader(http.StatusFound)
							fmt.Fprintf(w, `<script src="%s/hop.js"></script>`, hopOnly.URL)
						case "/page":
							w.Header().Set("Content-Type", "text/html")
							w.Header().Set("Server", "nginx")
							w.WriteHeader(http.StatusForbidden)
							// Discovery must continue beyond the five fetch candidates.
							for i := 0; i < 6; i++ {
								fmt.Fprintf(w, `<script src="/local-%d.js"></script>`, i)
							}
							fmt.Fprintf(w, `<script src="%[1]s/private-path.js?private-query=1#private-fragment"></script>
<script src="%[1]s/private-path.js?private-query=1"></script>
<link rel=stylesheet href="%[1]s/private-style.css?private-query=2">
<script type=application/json src="%[2]s/ignored.json"></script>
<template><script src="%[2]s/template.js"></script></template>
<link rel=modulepreload href="%[2]s/preload.js">`, external.URL, hopOnly.URL)
						default:
							if r.Method != "GET" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Referer() != "" {
								t.Errorf("asset request policy changed: %s %#v", r.Method, r.Header)
							}
							if failAsset && r.URL.Path == "/local-0.js" {
								w.WriteHeader(http.StatusNotFound)
								return
							}
							w.Header().Set("Content-Type", "application/javascript")
							fmt.Fprint(w, "/* local fixture */")
						}
					}))
					defer server.Close()
					args := []string{"--redact-query"}
					if setting != "default" {
						args = append(args, "--assets="+setting)
					}
					switch format {
					case "json":
						args = append(args, "--json")
					case "color":
						args = append(args, "--color=always")
					default:
						args = append(args, "--no-color")
					}
					var stdout, stderr bytes.Buffer
					if code := cli.Run(append(args, server.URL+"/start"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
						t.Fatalf("code=%d stderr=%s", code, &stderr)
					}
					wantVisited := []string{"/start", "/page"}
					if setting == "true" {
						for i := 0; i < 5; i++ {
							wantVisited = append(wantVisited, fmt.Sprintf("/local-%d.js", i))
						}
					}
					mu.Lock()
					gotVisited := append([]string(nil), visited...)
					mu.Unlock()
					if !reflect.DeepEqual(gotVisited, wantVisited) {
						t.Fatalf("requests=%v want=%v", gotVisited, wantVisited)
					}
					if strings.Contains(stdout.String(), "private-") || strings.Contains(stdout.String(), hopOnly.URL) {
						t.Fatalf("full external URL or excluded scope leaked: %s", &stdout)
					}
					if format == "json" {
						var report output.Report
						if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
							t.Fatal(err)
						}
						if report.SchemaVersion != 1 || report.ResponseScope != "http_error_response" || len(report.Findings) != 1 || report.Findings[0].ID != "nginx" {
							t.Fatalf("page findings/scope changed: %+v", report)
						}
						if setting == "true" {
							a := report.Assets
							want := []output.ExternalOrigin{{Origin: external.URL, Scripts: 2, Stylesheets: 1}}
							collected := 5
							if failAsset {
								collected--
							}
							if a == nil || a.Status != "incomplete" || a.Reason != "reference_limit" || !a.Truncated || a.Attempted != 5 || a.Collected != collected || a.SkippedDeclarations != 4 || a.Duplicates != 0 || !reflect.DeepEqual(a.ExternalOrigins, want) || a.ExternalOriginsTruncated {
								t.Fatalf("asset metadata=%+v", a)
							}
						} else if report.Assets != nil {
							t.Fatalf("default output gained asset discovery: %+v", report.Assets)
						}
					} else {
						if !strings.Contains(stdout.String(), "nginx [web server]") {
							t.Fatalf("lost page finding: %s", &stdout)
						}
						if setting == "true" {
							if !strings.Contains(stdout.String(), "External asset origins skipped (not requested; declaration counts):") || !strings.Contains(stdout.String(), external.URL+" (scripts: 2, stylesheets: 1)") {
								t.Fatalf("missing discovery: %s", &stdout)
							}
						} else if strings.Contains(stdout.String(), "External asset origins") || strings.Contains(stdout.String(), external.URL) {
							t.Fatalf("default output gained discovery: %s", &stdout)
						}
					}
				})
			}
		}
	}
}
