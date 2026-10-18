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

func TestKestrelPageAndAssetHeaderIsolationThroughCLI(t *testing.T) {
	js, err := os.ReadFile("../detect/testdata/coverage/react-19-client.min.js")
	if err != nil {
		t.Fatal(err)
	}
	const body = `<p>ASP.NET C# .NET</p><script src="/runtime.js?token=private-query"></script>`
	for _, pageHeader := range []bool{false, true} {
		for _, preferHTML := range []bool{false, true} {
			for _, format := range []string{"plain", "color", "json"} {
				t.Run(fmt.Sprintf("page-header=%t/prefer-html=%t/%s", pageHeader, preferHTML, format), func(t *testing.T) {
					var mu sync.Mutex
					paths := []string{}
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						paths = append(paths, r.URL.Path)
						mu.Unlock()
						wantAccept := ""
						if r.URL.Path == "/page" && preferHTML {
							wantAccept = "text/html, application/xhtml+xml;q=0.9, */*;q=0.8"
						}
						if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Accept") != wantAccept || r.Header.Get("Accept-Encoding") != "gzip" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Referer() != "" || r.URL.Query().Get("token") != "private-query" {
							t.Errorf("unexpected request policy: %s %s %v", r.Method, r.URL, r.Header)
						}
						switch r.URL.Path {
						case "/page":
							w.Header().Set("Content-Type", "text/html")
							w.Header().Set("X-Powered-By", "ASP.NET")
							http.SetCookie(w, &http.Cookie{Name: "JSESSIONID", Value: "private-cookie"})
							if pageHeader {
								w.Header().Add("Server", "kEsTrEl")
								w.Header().Add("Server", "Kestrel")
							}
							w.WriteHeader(403)
							fmt.Fprint(w, body)
						case "/runtime.js":
							w.Header().Set("Content-Type", "text/javascript")
							w.Header().Set("Server", "Kestrel")
							w.Header().Set("X-Powered-By", "Express")
							fmt.Fprint(w, string(js))
						default:
							t.Errorf("unexpected request: %s", r.URL.Path)
							http.NotFound(w, r)
						}
					}))
					defer server.Close()
					args := []string{"--assets", "--redact-query", "--color=always"}
					if preferHTML {
						args = append(args, "--prefer-html")
					}
					if format == "plain" {
						args = append(args, "--no-color")
					} else if format == "json" {
						args = append(args, "--json")
					}
					var stdout, stderr bytes.Buffer
					if code := cli.Run(append(args, server.URL+"/page?token=private-query"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
						t.Fatalf("exit=%d stderr=%q", code, &stderr)
					}
					mu.Lock()
					visited := append([]string(nil), paths...)
					mu.Unlock()
					if !reflect.DeepEqual(visited, []string{"/page", "/runtime.js"}) {
						t.Errorf("unexpected requests: %v", visited)
					}
					for _, raw := range []string{"private-", "kEsTrEl", "ASP.NET", "C#", ".NET", "Express"} {
						if strings.Contains(stdout.String(), raw) {
							t.Errorf("raw value or unsupported implication leaked: %q", raw)
						}
					}
					if strings.Contains(stdout.String(), "\x1b") != (format == "color") {
						t.Error("incorrect color handling")
					}
					assetURL := server.URL + "/runtime.js?[redacted]"
					wantIDs := []string{"react"}
					if pageHeader {
						wantIDs = []string{"kestrel", "react"}
					}
					if format != "json" {
						strip := strings.NewReplacer("\x1b[32m", "", "\x1b[33m", "", "\x1b[0m", "")
						plain := strip.Replace(stdout.String())
						lines, want := []string{}, []string{"? React [JavaScript framework]"}
						if pageHeader {
							want = append([]string{"✓ Kestrel [web server]"}, want...)
						}
						for _, line := range strings.Split(plain, "\n") {
							if (strings.HasPrefix(line, "✓ ") || strings.HasPrefix(line, "? ")) && strings.Contains(line, " [") {
								lines = append(lines, line)
							}
						}
						if !reflect.DeepEqual(lines, want) || !strings.Contains(plain, "Asset: "+assetURL) || !strings.Contains(plain, "HTTP status: 403") {
							t.Errorf("unexpected terminal report: %s", &stdout)
						}
						if format == "color" && (!strings.Contains(stdout.String(), "\x1b[33m?\x1b[0m") || strings.Contains(stdout.String(), "\x1b[32m✓\x1b[0m Kestrel") != pageHeader) {
							t.Error("incorrect state colors")
						}
						return
					}
					var report output.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					pageURL := server.URL + "/page?[redacted]"
					if report.SchemaVersion != 1 || !report.QueryRedacted || report.URL != pageURL || report.FinalURL != pageURL || report.HTTPStatus != 403 || report.ResponseScope != "http_error_response" || report.BodyBytes != len(body) || report.Redirects == nil || len(report.Redirects) != 0 || len(report.Findings) != len(wantIDs) {
						t.Fatalf("unexpected metadata: %+v", report)
					}
					for i, id := range wantIDs {
						f := report.Findings[i]
						name, category, state, rule, url := "React", "javascript_framework", "inferred", "asset-client-runtime", assetURL
						signals := []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}
						if id == "kestrel" {
							name, category, state, rule, url = "Kestrel", "web_server", "detected", "server-header", ""
							signals = []output.Signal{{Source: "header", Name: "Server"}}
						}
						if f.ID != id || f.Name != name || f.Category != category || f.State != state || len(f.Evidence) != 1 {
							t.Fatalf("unexpected finding: %+v", f)
						}
						e := f.Evidence[0]
						if e.Description == "" || e.RuleID != rule || e.InferredFrom != "" || e.AssetURL != url || !reflect.DeepEqual(e.Signals, signals) {
							t.Errorf("unexpected evidence: %+v", e)
						}
					}
					if a := report.Assets; a == nil || a.Status != "complete" || a.Attempted != 1 || a.Collected != 1 || len(a.Items) != 1 || a.Items[0].URL != assetURL {
						t.Errorf("unexpected assets: %+v", a)
					}
				})
			}
		}
	}
}
