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
	"webscan/internal/detect"
	"webscan/internal/output"
)

func TestCLIMixedAssetFailuresIsolationAndRedaction(t *testing.T) {
	css, err := os.ReadFile("../detect/testdata/coverage/bootstrap-5.3.min.css")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	// Cross-kind text is a decoy, never extra evidence for the other technology.
	jsBody := buildManifestFixture + "\n" + string(css)
	cssBody := string(css) + "\n/* " + buildManifestFixture + " */"
	for _, scenario := range []struct {
		name, cssReason                 string
		jsFailed, lateFailure, disabled bool
	}{
		{name: "complete"},
		{name: "default-off", disabled: true},
		{name: "late-failure", lateFailure: true},
		{name: "js-failure-before-css", jsFailed: true},
		{name: "css-wrong-mime", cssReason: "unsuitable_content_type"},
		{name: "css-redirect", cssReason: "redirect_not_allowed"},
		{name: "css-truncated", cssReason: "request_or_body_error"},
		{name: "css-oversized", cssReason: "decoded_body_limit"},
	} {
		for _, format := range []string{"json", "plain", "color"} {
			for _, redact := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/redact=%t", scenario.name, format, redact), func(t *testing.T) {
					var mu sync.Mutex
					var requests []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, r.RequestURI)
						mu.Unlock()
						if r.Method != http.MethodGet || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
							t.Errorf("unexpected request method/credentials: %s", r.RequestURI)
						}
						switch r.URL.Path {
						case "/start":
							w.Header().Set("X-Powered-By", "Express")
							w.Header().Set("Location", "/page?private-page=1")
							w.WriteHeader(http.StatusFound)
						case "/page":
							w.Header().Set("Content-Type", "text/html")
							w.Header().Set("Server", "nginx")
							w.Header().Set("X-Powered-By", "Next.js")
							w.Header().Set("Set-Cookie", "unrelated=private-cookie; Path=/")
							fmt.Fprintf(w, `<style>%s</style><script>%s</script><script src="/script?private-js=1"></script><link rel="stylesheet" href="/style?private-css=1"><link rel="stylesheet" href="/style?private-css=1#duplicate">`, css, buildManifestFixture)
							if scenario.lateFailure {
								fmt.Fprint(w, `<script src="/late?private-late=1"></script>`)
							}
						case "/script", "/style", "/late":
							if r.Header.Get("Referer") != "" {
								t.Error("asset request included a referrer")
							}
							w.Header().Set("X-Powered-By", "Express")
							w.Header().Set("Server", "Apache")
							if r.URL.Path == "/late" || (r.URL.Path == "/script" && scenario.jsFailed) {
								w.Header().Set("Content-Type", "text/javascript")
								w.WriteHeader(http.StatusForbidden)
								fmt.Fprint(w, jsBody)
								return
							}
							if r.URL.Path == "/script" {
								w.Header().Set("Content-Type", "application/javascript")
								fmt.Fprint(w, jsBody)
								return
							}
							w.Header().Set("Content-Type", "text/css")
							switch scenario.name {
							case "css-wrong-mime":
								w.Header().Set("Content-Type", "text/javascript")
							case "css-redirect":
								w.Header().Set("Location", "/forbidden?private-destination=1")
								w.WriteHeader(http.StatusFound)
							case "css-truncated":
								w.Header().Set("Content-Length", fmt.Sprint(len(cssBody)+100))
							case "css-oversized":
								fmt.Fprint(w, cssBody+strings.Repeat(" ", 512<<10))
								return
							}
							fmt.Fprint(w, cssBody)
						default:
							t.Errorf("unexpected request: %s", r.RequestURI)
							w.WriteHeader(http.StatusNotFound)
						}
					}))
					defer server.Close()
					args := []string{}
					if !scenario.disabled {
						args = append(args, "--assets")
					}
					if redact {
						args = append(args, "--redact-query")
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
					if code := cli.Run(append(args, server.URL+"/start?private-start=1"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
						t.Fatalf("code=%d stderr=%s", code, &stderr)
					}
					wantRequests := []string{"/start?private-start=1", "/page?private-page=1"}
					if !scenario.disabled {
						wantRequests = append(wantRequests, "/script?private-js=1", "/style?private-css=1")
						if scenario.lateFailure {
							wantRequests = append(wantRequests, "/late?private-late=1")
						}
					}
					mu.Lock()
					gotRequests := append([]string(nil), requests...)
					mu.Unlock()
					if !reflect.DeepEqual(gotRequests, wantRequests) {
						t.Errorf("requests=%v want=%v", gotRequests, wantRequests)
					}
					for _, secret := range []string{"private-cookie", "private-body", "private-destination", "--bs-btn-", "self.__", "Express", "Apache"} {
						if strings.Contains(stdout.String(), secret) {
							t.Errorf("raw/other-response data leaked: %s", secret)
						}
					}
					if redact && strings.Contains(stdout.String(), "private-") {
						t.Fatal("query leaked into report")
					}
					url := func(path string) string {
						if redact {
							path, _, _ = strings.Cut(path, "?")
							path += "?[redacted]"
						}
						return server.URL + path
					}
					wantCSS := !scenario.disabled && scenario.cssReason == ""
					wantJS := !scenario.disabled && !scenario.jsFailed
					status, reason := "complete", ""
					if scenario.cssReason != "" || scenario.jsFailed || scenario.lateFailure {
						status, reason = "incomplete", "asset_failures_or_skips"
					}
					if format != "json" {
						text := stdout.String()
						text = strings.NewReplacer("\x1b[32m", "", "\x1b[33m", "", "\x1b[0m", "").Replace(text)
						if !strings.Contains(text, "✓ Next.js [framework]") || !strings.Contains(text, "✓ nginx [web server]") || strings.Contains(text, "? Bootstrap [UI framework]") != wantCSS {
							t.Fatalf("findings=%s", text)
						}
						for _, expected := range []struct {
							path    string
							present bool
						}{{"/script?private-js=1", wantJS}, {"/style?private-css=1", wantCSS}} {
							if strings.Contains(text, "    Asset: "+url(expected.path)+"\n") != expected.present {
								t.Errorf("unexpected evidence for %s: %s", expected.path, text)
							}
						}
						if scenario.disabled {
							if strings.Contains(text, "Assets:") {
								t.Error("default gained asset report")
							}
						} else if !strings.Contains(text, "Assets: "+status) {
							t.Errorf("missing collection status: %s", text)
						}
						return
					}
					var report output.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					if report.CatalogSize != engine.Len() || report.QueryRedacted != redact || report.URL != url(wantRequests[0]) || report.FinalURL != url(wantRequests[1]) || !reflect.DeepEqual(report.Redirects, []output.Redirect{{FromURL: url(wantRequests[0]), ToURL: url(wantRequests[1]), StatusCode: 302}}) {
						t.Fatalf("report metadata=%+v", report)
					}
					wantIDs := []string{"nextjs", "nginx"}
					if wantCSS {
						wantIDs = append([]string{"bootstrap"}, wantIDs...)
					}
					var ids []string
					for _, f := range report.Findings {
						ids = append(ids, f.ID)
						state := "detected"
						var rules, urls []string
						var sources []string
						switch f.ID {
						case "bootstrap":
							state = "inferred"
							rules, urls, sources = []string{"asset-css-banner-and-buttons"}, []string{url("/style?private-css=1")}, []string{"asset_css"}
						case "nextjs":
							if wantJS {
								rules, urls, sources = append(rules, "asset-build-manifest"), append(urls, url("/script?private-js=1")), append(sources, "asset_javascript")
							}
							rules, urls, sources = append(rules, "powered-by-header"), append(urls, ""), append(sources, "header")
						case "nginx":
							rules, urls, sources = []string{"server-header"}, []string{""}, []string{"header"}
						default:
							t.Fatalf("unexpected finding: %+v", f)
						}
						if f.State != state || len(f.Evidence) != len(rules) {
							t.Fatalf("finding=%+v", f)
						}
						for i, e := range f.Evidence {
							if e.RuleID != rules[i] || e.AssetURL != urls[i] || e.InferredFrom != "" || len(e.Signals) == 0 {
								t.Fatalf("evidence=%+v", e)
							}
							for _, signal := range e.Signals {
								if signal.Source != sources[i] {
									t.Errorf("wrong-source evidence=%+v", e)
								}
							}
						}
					}
					if !reflect.DeepEqual(ids, wantIDs) {
						t.Fatalf("IDs=%v want=%v", ids, wantIDs)
					}
					if scenario.disabled {
						if report.Assets != nil {
							t.Error("default gained asset report")
						}
						return
					}
					collected := 0
					if wantCSS {
						collected++
					}
					if wantJS {
						collected++
					}
					if report.Assets == nil || report.Assets.Status != status || report.Assets.Reason != reason || report.Assets.Attempted != len(wantRequests)-2 || report.Assets.Collected != collected || report.Assets.Duplicates != 1 || len(report.Assets.Items) != len(wantRequests)-2 {
						t.Fatalf("assets=%+v", report.Assets)
					}
					for i, item := range report.Assets.Items {
						wantStatus, wantReason := "collected", ""
						if (i == 0 && scenario.jsFailed) || i == 2 {
							wantStatus, wantReason = "failed", "unsuccessful_status"
						}
						if i == 1 && scenario.cssReason != "" {
							wantStatus, wantReason = "failed", scenario.cssReason
						}
						if item.URL != url(wantRequests[i+2]) || item.Status != wantStatus || item.Reason != wantReason {
							t.Errorf("item=%+v", item)
						}
					}
				})
			}
		}
	}
}
