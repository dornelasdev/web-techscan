package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/output"
)

// Exercise the actual HTML fixtures used by the documented manual smoke check.
// Asset references are kept local so a regression cannot contact a public CDN.
func TestReleaseFixturesThroughCLI(t *testing.T) {
	for _, fixture := range []string{"next-pages.html", "next-cdn.html"} {
		data, err := os.ReadFile("../detect/testdata/coverage/" + fixture)
		if err != nil {
			t.Fatal(err)
		}
		for _, direct := range []bool{false, true} {
			for _, format := range []string{"terminal", "json"} {
				t.Run(fmt.Sprintf("%s/direct=%t/%s", fixture, direct, format), func(t *testing.T) {
					var mu sync.Mutex
					var requests []string
					body := strings.ReplaceAll(string(data), "https://cdn.example.test", "")
					body = strings.Replace(body, "</head>", `<link rel="stylesheet" href="/style.css"></head>`, 1)
					body = strings.Replace(body, "</body>", `<a href="/other-page">Other page</a></body>`, 1)
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, r.URL.Path)
						mu.Unlock()
						switch r.URL.Path {
						case "/start":
							w.Header().Set("Server", "nginx")
							http.Redirect(w, r, "/fixture", http.StatusFound)
						case "/fixture":
							w.Header().Set("Content-Type", "text/html; charset=utf-8")
							if direct {
								w.Header().Set("X-Powered-By", "Next.js")
							}
							fmt.Fprint(w, body)
						default:
							http.NotFound(w, r)
						}
					}))
					defer server.Close()
					args := []string{"--no-color"}
					if format == "json" {
						args = append(args, "--json")
					}
					var stdout, stderr bytes.Buffer
					code := cli.Run(append(args, server.URL+"/start#fragment"), &stdout, &stderr, "dev")
					if code != 0 || stderr.Len() != 0 {
						t.Fatalf("exit=%d stderr=%q", code, stderr.String())
					}
					mu.Lock()
					visited := append([]string(nil), requests...)
					mu.Unlock()
					if !reflect.DeepEqual(visited, []string{"/start", "/fixture"}) {
						t.Errorf("unexpected requests (assets and links must not be fetched): %v", visited)
					}
					state, marker, evidenceCount := "inferred", "?", 1
					if direct {
						state, marker, evidenceCount = "detected", "✓", 2
					}
					if format == "terminal" {
						for _, want := range []string{server.URL + "/fixture", "Redirects: 1", marker + " Next.js [framework]", "__NEXT_DATA__"} {
							if !strings.Contains(stdout.String(), want) {
								t.Errorf("missing %q in output: %s", want, &stdout)
							}
						}
						for _, absent := range []string{"nginx", "[language]", "\x1b", "#fragment"} {
							if strings.Contains(stdout.String(), absent) {
								t.Errorf("unexpected %q in output: %s", absent, &stdout)
							}
						}
						return
					}
					var report output.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					if report.SchemaVersion != 1 || report.HTTPStatus != 200 || report.ResponseScope != "final_response" || report.BodyBytes != len(body) {
						t.Errorf("unexpected response metadata: %+v", report)
					}
					if report.URL != server.URL+"/start" || report.FinalURL != server.URL+"/fixture" || len(report.Redirects) != 1 {
						t.Errorf("unexpected URL metadata: %+v", report)
					}
					if len(report.Findings) != 1 || report.Findings[0].ID != "nextjs" || report.Findings[0].State != state {
						t.Fatalf("want only Next.js (%s), got %+v", state, report.Findings)
					}
					if len(report.Findings[0].Evidence) != evidenceCount {
						t.Errorf("want %d evidence entries, got %+v", evidenceCount, report.Findings[0].Evidence)
					}
				})
			}
		}
	}
}
