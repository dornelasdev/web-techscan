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

func TestCLIReactRuntimeCoexistence(t *testing.T) {
	for _, fixture := range []string{"react-dom-18.min.js", "react-dom-19.min.js"} {
		t.Run(fixture, func(t *testing.T) { testCLIReactRuntimeCoexistence(t, fixture) })
	}
}

func testCLIReactRuntimeCoexistence(t *testing.T, fixture string) {
	t.Helper()
	client, err := os.ReadFile("../detect/testdata/coverage/react-19-client.min.js")
	if err != nil {
		t.Fatal(err)
	}
	dom, err := os.ReadFile("../detect/testdata/coverage/" + fixture)
	if err != nil {
		t.Fatal(err)
	}
	// Split the renderer's five conditions across two accepted files.
	keys := `var f="__reactFiber$"+k,p="__reactProps$"+k,c="__reactContainer$"+k;`
	errors := `var u="https://reactjs.org/docs/error-decoder.html?invariant="+n;var m="Minified React error #"+n+"; visit "+u;`
	otherFixture := "react-dom-19.min.js"
	if fixture == "react-dom-19.min.js" {
		errors = strings.ReplaceAll(errors, "https://reactjs.org/docs/error-decoder.html?invariant=", "https://react.dev/errors/")
		otherFixture = "react-dom-18.min.js"
	}
	otherDOM, err := os.ReadFile("../detect/testdata/coverage/" + otherFixture)
	if err != nil {
		t.Fatal(err)
	}
	compat := `e.version="18.3.1";e.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED=n;Symbol.for("react.element");`
	for _, format := range []string{"json", "plain", "color"} {
		for _, redact := range []bool{false, true} {
			for _, tc := range []struct {
				name, one, two string
				secondFails    bool
				rules, paths   []string
			}{
				{"same-body", string(client) + string(dom), "generic", false, []string{"asset-client-runtime", "asset-dom-runtime"}, []string{"/one", "/one"}},
				{"separate-bodies", string(client), string(dom), false, []string{"asset-client-runtime", "asset-dom-runtime"}, []string{"/one", "/two"}},
				{"reverse-bodies", string(dom), string(client), false, []string{"asset-client-runtime", "asset-dom-runtime"}, []string{"/two", "/one"}},
				{"failed-renderer", string(client), string(dom), true, []string{"asset-client-runtime"}, []string{"/one"}},
				{"split-renderer", keys, errors, false, nil, nil},
				{"compat-decoy", compat, "generic", false, nil, nil},
				{"both-url-forms-same-body", string(dom) + string(otherDOM), "generic", false, []string{"asset-dom-runtime"}, []string{"/one"}},
				{"both-url-forms-separate-bodies", string(dom), string(otherDOM), false, []string{"asset-dom-runtime", "asset-dom-runtime"}, []string{"/one", "/two"}},
			} {
				t.Run(fmt.Sprintf("%s/%s/redact=%t", tc.name, format, redact), func(t *testing.T) {
					var mu sync.Mutex
					var requests []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, r.RequestURI)
						mu.Unlock()
						if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "webscan" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
							t.Errorf("unexpected request policy: %s %s", r.Method, r.RequestURI)
						}
						if r.URL.Path == "/" {
							w.Header().Set("Content-Type", "text/html")
							w.Header().Set("X-Powered-By", "Next.js")
							w.Header().Set("Set-Cookie", "private-cookie=private-cookie-value; Path=/")
							fmt.Fprint(w, `<script src="/one?private-token=1"></script><script src="/two?private-token=1"></script><script src="/one?private-token=1#duplicate"></script>`)
							return
						}
						if r.Header.Get("Referer") != "" {
							t.Error("asset referrer forwarded")
						}
						w.Header().Set("Content-Type", "application/javascript")
						w.Header().Set("X-Powered-By", "Express") // Never page evidence.
						switch r.URL.Path {
						case "/one":
							fmt.Fprint(w, tc.one)
						case "/two":
							if tc.secondFails {
								w.WriteHeader(http.StatusForbidden)
							}
							fmt.Fprint(w, tc.two)
						default:
							t.Errorf("unexpected request: %s", r.RequestURI)
							w.WriteHeader(http.StatusNotFound)
						}
					}))
					defer server.Close()
					args := []string{"--assets"}
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
					if code := cli.Run(append(args, server.URL), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
						t.Fatalf("code=%d stderr=%s", code, &stderr)
					}
					mu.Lock()
					gotRequests := append([]string(nil), requests...)
					mu.Unlock()
					if !reflect.DeepEqual(gotRequests, []string{"/", "/one?private-token=1", "/two?private-token=1"}) {
						t.Errorf("requests=%v", gotRequests)
					}
					query := "?private-token=1"
					if redact {
						query = "?[redacted]"
						if strings.Contains(stdout.String(), "private-token") {
							t.Error("query leaked")
						}
					}
					for _, raw := range []string{"private-runtime-body", "private-cookie-value", "__reactFiber$", "Minified React error #", "__CLIENT_INTERNALS", "__DOM_INTERNALS", "react.dev/errors/", "reactjs.org/docs/error-decoder", "Express", "18.3.1", "19.1.0"} {
						if strings.Contains(stdout.String(), raw) {
							t.Errorf("raw body/header leaked: %s", raw)
						}
					}
					if format == "json" {
						var report output.Report
						if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
							t.Fatal(err)
						}
						wantFindings := 1
						if len(tc.rules) != 0 {
							wantFindings++
						}
						if len(report.Findings) != wantFindings || report.Findings[0].ID != "nextjs" || report.Findings[0].State != "detected" || report.QueryRedacted != redact {
							t.Fatalf("report=%+v", report)
						}
						wantStatus, collected := "complete", 2
						if tc.secondFails {
							wantStatus, collected = "incomplete", 1
						}
						if report.Assets == nil || report.Assets.Mode != "fingerprint_inspection" || report.Assets.Status != wantStatus || report.Assets.Attempted != 2 || report.Assets.Duplicates != 1 || report.Assets.Collected != collected || len(report.Assets.Items) != 2 {
							t.Fatalf("assets=%+v", report.Assets)
						}
						for i, item := range report.Assets.Items {
							if item.URL != server.URL+[]string{"/one", "/two"}[i]+query {
								t.Errorf("asset URL=%s", item.URL)
							}
							status, reason, code := "collected", "", http.StatusOK
							if i == 1 && tc.secondFails {
								status, reason, code = "failed", "unsuccessful_status", http.StatusForbidden
							}
							if item.Kind != "javascript" || item.Status != status || item.Reason != reason || item.HTTPStatus != code {
								t.Errorf("item=%+v", item)
							}
						}
						if len(tc.rules) == 0 {
							return
						}
						f := report.Findings[1]
						if f.ID != "react" || f.Category != "framework" || f.State != "inferred" || len(f.Evidence) != len(tc.rules) {
							t.Fatalf("finding=%+v", f)
						}
						for i, e := range f.Evidence {
							count := 2
							if tc.rules[i] == "asset-dom-runtime" {
								count = 5
							}
							if e.RuleID != tc.rules[i] || e.AssetURL != server.URL+tc.paths[i]+query || len(e.Signals) != count {
								t.Fatalf("evidence=%+v", e)
							}
							for _, signal := range e.Signals {
								if signal.Source != "asset_javascript" {
									t.Errorf("signal=%+v", signal)
								}
							}
						}
					} else {
						marker := "?"
						if format == "color" {
							marker = "\x1b[33m?\x1b[0m"
						}
						if len(tc.rules) == 0 {
							if strings.Contains(stdout.String(), "React [framework]") {
								t.Error("unexpected React finding")
							}
						} else {
							if strings.Count(stdout.String(), marker+" React [framework]") != 1 {
								t.Errorf("terminal=%s", &stdout)
							}
							for _, path := range tc.paths {
								if !strings.Contains(stdout.String(), "Asset: "+server.URL+path+query) {
									t.Errorf("missing provenance: %s", &stdout)
								}
							}
						}
					}
				})
			}
		}
	}
}
