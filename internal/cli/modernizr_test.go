package cli_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/detect"
	"webscan/internal/output"
)

func TestCLIModernizrV2Assets(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	const factory = `host.Modernizr=function(a,b,c){return {};};`
	const prefixes = `feature._domPrefixes=dom;feature._cssomPrefixes=css;`
	for _, tc := range []struct {
		name, kind, fixture, mime, reason string
		enabled, want, external, allowed  bool
	}{
		{name: "default-off"},
		{name: "compact", enabled: true, want: true},
		{name: "readable", fixture: "modernizr-v2-core.js", enabled: true, want: true},
		{name: "gzip", kind: "gzip", mime: "application/x-javascript", enabled: true, want: true},
		{name: "split-files", kind: "split", enabled: true},
		{name: "inline-only", kind: "inline", enabled: true},
		{name: "redirect-hop-only", kind: "hop", enabled: true},
		{name: "filename-only", kind: "filename", enabled: true},
		{name: "factory-only", kind: "factory", enabled: true},
		{name: "prefixes-only", kind: "prefixes", enabled: true},
		{name: "excluded-origin", enabled: true, external: true},
		{name: "allowed-origin", enabled: true, external: true, allowed: true, want: true},
		{name: "failed-status", kind: "status", reason: "unsuccessful_status", enabled: true},
		{name: "wrong-mime", mime: "text/css", reason: "unsuitable_content_type", enabled: true},
		{name: "asset-redirect", kind: "redirect", reason: "redirect_not_allowed", enabled: true},
		{name: "oversized-prefix", kind: "oversized", reason: "decoded_body_limit", enabled: true},
		{name: "incomplete-prefix", kind: "incomplete", reason: "request_or_body_error", enabled: true},
		{name: "later-failure", kind: "late", enabled: true, want: true},
	} {
		formats := []string{"json"}
		if tc.name == "compact" || tc.name == "default-off" || tc.kind == "late" {
			formats = append(formats, "plain", "color")
		}
		for _, format := range formats {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				fixture := tc.fixture
				if fixture == "" {
					fixture = "modernizr-v2-core.min.js"
				}
				data, err := os.ReadFile("../detect/testdata/coverage/" + fixture)
				if err != nil {
					t.Fatal(err)
				}
				body := string(data) + "\n/* private-modernizr-body */"
				mime := tc.mime
				if mime == "" {
					mime = "application/javascript"
				}
				path := "/renamed?private-asset"
				if tc.kind == "filename" {
					path = "/modernizr.min.js?private-asset"
				}
				assetOrigin := ""
				var mu sync.Mutex
				requests := []string{}
				var externalRequests atomic.Int32
				handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					requests = append(requests, r.RequestURI)
					mu.Unlock()
					wantReferer := ""
					if r.URL.Path == "/page" {
						wantReferer = "http://" + r.Host + "/start?private-start"
					}
					if r.Method != http.MethodGet || r.UserAgent() != "webscan" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Referer() != wantReferer {
						t.Errorf("request policy=%s %v", r.Method, r.Header)
					}
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Location", "/page?private-page")
						w.Header().Set("Content-Type", "text/html")
						w.WriteHeader(http.StatusFound)
						fmt.Fprint(w, "<script>"+body+`</script><script src="/hop-only.js"></script>`)
					case "/page":
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Server", "nginx")
						w.Header().Add("Set-Cookie", "fixture=private-cookie-value; Path=/")
						w.WriteHeader(http.StatusForbidden)
						if tc.kind == "hop" {
							fmt.Fprint(w, "<p>final response</p>")
							return
						}
						fmt.Fprint(w, "<script>"+body+"</script>")
						if tc.kind != "inline" {
							ref := assetOrigin + path
							fmt.Fprintf(w, `<script src="%s"></script><script src="%s#duplicate"></script>`, ref, ref)
						}
						if tc.kind == "split" {
							fmt.Fprint(w, `<script src="/part"></script>`)
						}
						if tc.kind == "late" {
							fmt.Fprint(w, `<script src="/fail"></script>`)
						}
					case "/renamed", "/modernizr.min.js":
						w.Header().Set("Content-Type", mime)
						w.Header().Set("X-Powered-By", "Express") // Never a page signal.
						content := body
						switch tc.kind {
						case "factory", "split":
							content = factory
						case "prefixes":
							content = prefixes
						case "filename":
							content = "console.log('generic');"
						case "oversized":
							content += "/*" + strings.Repeat("0", 512<<10) + "*/"
						case "incomplete":
							w.Header().Set("Content-Length", fmt.Sprint(len(content)+100))
						case "gzip":
							w.Header().Set("Content-Encoding", "gzip")
						}
						status := http.StatusOK
						if tc.kind == "status" {
							status = http.StatusForbidden
						} else if tc.kind == "redirect" {
							status = http.StatusFound
							w.Header().Set("Location", "/redirect-destination")
						}
						w.WriteHeader(status)
						if tc.kind == "gzip" {
							writer := gzip.NewWriter(w)
							if _, err := writer.Write([]byte(content)); err != nil {
								t.Error(err)
							}
							if err := writer.Close(); err != nil {
								t.Error(err)
							}
						} else {
							fmt.Fprint(w, content)
						}
					case "/part":
						w.Header().Set("Content-Type", "application/javascript")
						fmt.Fprint(w, prefixes)
					case "/fail":
						w.Header().Set("Content-Type", "application/javascript")
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, "private-failed-body")
					default:
						t.Errorf("unexpected request: %s", r.RequestURI)
						w.WriteHeader(http.StatusNotFound)
					}
				})
				if tc.external {
					external := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						externalRequests.Add(1)
						handler.ServeHTTP(w, r)
					}))
					defer external.Close()
					assetOrigin = external.URL
				}
				server := httptest.NewServer(handler)
				defer server.Close()
				args := []string{"--redact-query"}
				if tc.enabled {
					args = append(args, "--assets")
				}
				if tc.allowed {
					args = append(args, "--asset-origin", assetOrigin)
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
				if code := cli.Run(append(args, server.URL+"/start?private-start"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("code=%d stderr=%s", code, &stderr)
				}
				wantRequests := []string{"/start?private-start", "/page?private-page"}
				if tc.enabled && tc.kind != "inline" && tc.kind != "hop" && (!tc.external || tc.allowed) {
					wantRequests = append(wantRequests, path)
					if tc.kind == "split" {
						wantRequests = append(wantRequests, "/part")
					} else if tc.kind == "late" {
						wantRequests = append(wantRequests, "/fail")
					}
				}
				mu.Lock()
				gotRequests := append([]string(nil), requests...)
				mu.Unlock()
				wantExternal := int32(0)
				if tc.allowed {
					wantExternal = 1
				}
				if !reflect.DeepEqual(gotRequests, wantRequests) || externalRequests.Load() != wantExternal {
					t.Errorf("requests=%v want=%v external=%d", gotRequests, wantRequests, externalRequests.Load())
				}
				for _, raw := range []string{"private-", "_domPrefixes", "_cssomPrefixes", "2.6.2", "2.8.3", "Express"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw response/query/version leaked: %q", raw)
					}
				}
				origin := assetOrigin
				if origin == "" {
					origin = server.URL
				}
				assetURL := origin + strings.SplitN(path, "?", 2)[0] + "?[redacted]"
				if format != "json" {
					marker := "?"
					if format == "color" {
						marker = "\x1b[33m?\x1b[0m"
					}
					if strings.Contains(stdout.String(), marker+" Modernizr [JavaScript library]") != tc.want || !strings.Contains(stdout.String(), "nginx [web server]") || (tc.want && !strings.Contains(stdout.String(), "Asset: "+assetURL)) {
						t.Errorf("terminal=%s", &stdout)
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				wantIDs := []string{"nginx"}
				if tc.want {
					wantIDs = []string{"modernizr", "nginx"}
				}
				var ids []string
				for _, finding := range report.Findings {
					ids = append(ids, finding.ID)
				}
				if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || !report.QueryRedacted || report.HTTPStatus != 403 || report.ResponseScope != "http_error_response" || report.URL != server.URL+"/start?[redacted]" || report.FinalURL != server.URL+"/page?[redacted]" || len(report.Redirects) != 1 || !reflect.DeepEqual(ids, wantIDs) {
					t.Fatalf("report=%+v", report)
				}
				if tc.want {
					finding := report.Findings[0]
					if finding.Name != "Modernizr" || finding.Category != "javascript_library" || finding.State != "inferred" || len(finding.Evidence) != 1 {
						t.Fatalf("finding=%+v", finding)
					}
					e := finding.Evidence[0]
					if e.RuleID != "asset-v2-core-runtime" || e.AssetURL != assetURL || e.StyleBlock != 0 || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []output.Signal{{Source: "asset_javascript"}, {Source: "asset_javascript"}}) {
						t.Errorf("evidence=%+v", e)
					}
				}
				if !tc.enabled {
					if report.Assets != nil {
						t.Error("default scan included asset collection")
					}
					return
				}
				attempted := len(wantRequests) - 2
				collected, status := attempted, "complete"
				if tc.reason != "" || tc.kind == "late" {
					collected--
					status = "incomplete"
				}
				if report.Assets == nil || report.Assets.Attempted != attempted || report.Assets.Collected != collected || report.Assets.Status != status || len(report.Assets.Items) != attempted || report.Assets.Budget.Profile != "standard" {
					t.Fatalf("collection=%+v", report.Assets)
				}
				if attempted > 0 && (report.Assets.Items[0].URL != assetURL || report.Assets.Items[0].Reason != tc.reason || report.Assets.Duplicates != 1) {
					t.Errorf("item/deduplication=%+v", report.Assets)
				}
				if tc.external {
					if tc.allowed {
						if !reflect.DeepEqual(report.Assets.AllowedOrigins, []string{assetOrigin}) || len(report.Assets.ExternalOrigins) != 0 {
							t.Errorf("allowed scope=%+v", report.Assets)
						}
					} else if !reflect.DeepEqual(report.Assets.ExternalOrigins, []output.ExternalOrigin{{Origin: assetOrigin, Scripts: 2}}) || report.Assets.SkippedDeclarations != 2 {
						t.Errorf("excluded scope=%+v", report.Assets)
					}
				}
			})
		}
	}
}
