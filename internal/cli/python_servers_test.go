package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/output"
)

func TestPythonHTTPServerPageAndAssetIsolationThroughCLI(t *testing.T) {
	js, err := os.ReadFile("../detect/testdata/coverage/react-19-client.min.js")
	if err != nil {
		t.Fatal(err)
	}
	const body = `<p>Flask FastAPI Python</p><script src="/runtime.js?token=private-query"></script>`
	for _, tech := range []struct{ id, name, banner, other string }{
		{"gunicorn", "Gunicorn", "gUnIcOrN", "uViCoRn"},
		{"uvicorn", "Uvicorn", "uViCoRn", "gUnIcOrN"},
	} {
		for _, pageHeader := range []bool{false, true} {
			for _, prefer := range []bool{false, true} {
				for _, format := range []string{"plain", "color", "json"} {
					t.Run(fmt.Sprintf("%s/page=%t/prefer=%t/%s", tech.id, pageHeader, prefer, format), func(t *testing.T) {
						var mu sync.Mutex
						paths := []string{}
						server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
							mu.Lock()
							paths = append(paths, r.URL.Path)
							mu.Unlock()
							wantAccept := ""
							if r.URL.Path == "/page" && prefer {
								wantAccept = "text/html, application/xhtml+xml;q=0.9, */*;q=0.8"
							}
							if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Accept") != wantAccept || r.Header.Get("Accept-Encoding") != "gzip" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Referer() != "" || r.URL.Query().Get("token") != "private-query" {
								t.Errorf("unexpected request policy: %s %s %v", r.Method, r.URL, r.Header)
							}
							switch r.URL.Path {
							case "/page":
								w.Header().Set("Content-Type", "text/html")
								w.Header().Set("X-Server", tech.banner)
								w.Header().Set("X-Powered-By", "FastAPI")
								http.SetCookie(w, &http.Cookie{Name: "session", Value: "private-cookie"})
								if pageHeader {
									w.Header().Add("Server", tech.banner)
									w.Header().Add("Server", tech.banner)
								}
								w.WriteHeader(403)
								fmt.Fprint(w, body)
							case "/runtime.js":
								w.Header().Set("Content-Type", "text/javascript")
								w.Header().Add("Server", tech.banner)
								w.Header().Add("Server", tech.other)
								fmt.Fprint(w, string(js))
							default:
								t.Errorf("unexpected request: %s", r.URL.Path)
								http.NotFound(w, r)
							}
						}))
						defer server.Close()
						args := []string{"--assets", "--redact-query", "--color=always"}
						if prefer {
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
						for _, raw := range []string{"private-", tech.banner, tech.other, "Flask", "FastAPI", "Python"} {
							if strings.Contains(stdout.String(), raw) {
								t.Errorf("raw value or unsupported implication leaked: %q", raw)
							}
						}
						ids := []string{"react"}
						if pageHeader {
							ids = append(ids, tech.id)
						}
						sort.Strings(ids)
						want := map[string]mixedFinding{
							tech.id: {tech.id, tech.name, "web_server", "web server", "detected", []mixedEvidence{mixedHeader("server-header", "Server")}},
							"react": {"react", "React", "javascript_framework", "JavaScript framework", "inferred", []mixedEvidence{{rule: "asset-client-runtime", signals: []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}}}},
						}
						assetURL := server.URL + "/runtime.js?[redacted]"
						if strings.Contains(stdout.String(), "\x1b") != (format == "color") {
							t.Error("incorrect color handling")
						}
						if format != "json" {
							strip := strings.NewReplacer("\x1b[32m", "", "\x1b[33m", "", "\x1b[0m", "")
							gotLines, wantLines := []string{}, []string{}
							for _, line := range strings.Split(stdout.String(), "\n") {
								plain := strip.Replace(line)
								if (strings.HasPrefix(plain, "✓ ") || strings.HasPrefix(plain, "? ")) && strings.Contains(plain, " [") {
									gotLines = append(gotLines, line)
								}
							}
							for _, id := range ids {
								f := want[id]
								marker, color := "?", "33"
								if f.state == "detected" {
									marker, color = "✓", "32"
								}
								if format == "color" {
									marker = "\x1b[" + color + "m" + marker + "\x1b[0m"
								}
								wantLines = append(wantLines, marker+" "+f.name+" ["+f.label+"]")
							}
							if !reflect.DeepEqual(gotLines, wantLines) || !strings.Contains(stdout.String(), "Asset: "+assetURL) || !strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") {
								t.Errorf("unexpected terminal report: %s", &stdout)
							}
							return
						}
						var report output.Report
						if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
							t.Fatal(err)
						}
						pageURL := server.URL + "/page?[redacted]"
						if report.SchemaVersion != 1 || report.CatalogSize != 38 || !report.QueryRedacted || report.URL != pageURL || report.FinalURL != pageURL || report.HTTPStatus != 403 || report.ResponseScope != "http_error_response" || report.BodyBytes != len(body) || report.Redirects == nil || len(report.Redirects) != 0 || len(report.Findings) != len(ids) {
							t.Fatalf("unexpected metadata: %+v", report)
						}
						for i, id := range ids {
							f, expected := report.Findings[i], want[id]
							if f.ID != id || f.Name != expected.name || f.Category != expected.category || f.State != expected.state || len(f.Evidence) != 1 {
								t.Fatalf("unexpected finding: %+v", f)
							}
							e, url := f.Evidence[0], ""
							if id == "react" {
								url = assetURL
							}
							if e.RuleID != expected.evidence[0].rule || e.Description == "" || e.InferredFrom != "" || e.AssetURL != url || !reflect.DeepEqual(e.Signals, expected.evidence[0].signals) {
								t.Errorf("unexpected evidence: %+v", e)
							}
						}
						if a := report.Assets; a == nil || a.Status != "complete" || a.Attempted != 1 || a.Collected != 1 || len(a.Items) != 1 || a.Items[0].URL != assetURL || a.Items[0].HTTPStatus != 200 || a.Items[0].Status != "collected" {
							t.Errorf("unexpected asset metadata: %+v", a)
						}
					})
				}
			}
		}
	}
}
