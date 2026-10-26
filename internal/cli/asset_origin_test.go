package cli_test

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

func TestCLIAssetOriginValidation(t *testing.T) {
	for _, args := range [][]string{
		{"--asset-origin", "https://cdn.test", "https://page.test"},
		{"--assets=false", "--asset-origin", "https://cdn.test", "https://page.test"},
		{"--assets", "--asset-origin", "https://cdn.test"},
		{"--assets", "--version", "--asset-origin", "https://cdn.test"},
		{"--techs", "--asset-origin", "https://cdn.test"},
		{"--techs", "--asset-origin="},
		{"--assets", "--asset-origin"},
	} {
		var stdout, stderr bytes.Buffer
		if code := cli.Run(args, &stdout, &stderr, "dev"); code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Errorf("args=%v exit=%d stdout=%q stderr=%q", args, code, &stdout, &stderr)
		}
	}
	for _, raw := range []string{"", "cdn.test", "https://*.test", "https://private-user:private-password@cdn.test", "https://cdn.test/private-path", "https://cdn.test/?private-query", "https://cdn.test/#private-fragment", "https://cdn.test\n"} {
		var stdout, stderr bytes.Buffer
		if code := cli.Run([]string{"--assets", "--asset-origin=" + raw, "https://page.test"}, &stdout, &stderr, "dev"); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "asset-origin") || strings.Contains(stderr.String(), "private-") {
			t.Errorf("unsafe validation raw=%q exit=%d stdout=%q stderr=%q", raw, code, &stdout, &stderr)
		}
	}
	args := []string{"--assets"}
	for i := 0; i < 21; i++ {
		args = append(args, "--asset-origin", fmt.Sprintf("https://cdn-%d.test", i))
	}
	var stdout, stderr bytes.Buffer
	if code := cli.Run(append(args, "https://page.test"), &stdout, &stderr, "dev"); code != 2 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "at most 20") {
		t.Errorf("origin cap exit=%d stderr=%s", code, &stderr)
	}
}

func TestCLIAllowedAssetOrigins(t *testing.T) {
	js, err := os.ReadFile("../detect/testdata/coverage/react-19-client.min.js")
	if err != nil {
		t.Fatal(err)
	}
	css, err := os.ReadFile("../detect/testdata/coverage/bootstrap-5.3.min.css")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                                                       string
		assets, allow, duplicate, second, wrongMIME, bounded, gzip bool
	}{
		{name: "page-only"},
		{name: "same-origin-default", assets: true},
		{name: "allowed", assets: true, allow: true},
		{name: "normalized-duplicate", assets: true, allow: true, duplicate: true},
		{name: "two-origins", assets: true, allow: true, second: true},
		{name: "wrong-js-mime", assets: true, allow: true, wrongMIME: true},
		{name: "shared-attempt-cap-and-failures", assets: true, allow: true, bounded: true},
		{name: "gzip-and-page-preference", assets: true, allow: true, gzip: true},
	} {
		for _, format := range []string{"json", "plain", "color"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				var mu sync.Mutex
				visited := []string{}
				record := func(prefix string, r *http.Request) {
					mu.Lock()
					visited = append(visited, prefix+r.URL.Path)
					mu.Unlock()
					wantAccept := ""
					if prefix == "page:" && (r.URL.Path == "/start" || r.URL.Path == "/page") && tc.gzip {
						wantAccept = "text/html, application/xhtml+xml;q=0.9, */*;q=0.8"
					}
					if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Accept") != wantAccept || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
						t.Errorf("unexpected request policy: %s %#v", r.Method, r.Header)
					}
					if (prefix != "page:" || r.URL.Path == "/local.js") && r.Referer() != "" {
						t.Errorf("asset forwarded referrer: %q", r.Referer())
					}
				}
				other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					record("other:", r)
					if !tc.second || r.URL.Path != "/other.js" {
						t.Errorf("unselected origin/path contacted: %s", r.URL)
					}
					w.Header().Set("Content-Type", "text/javascript")
					fmt.Fprint(w, "/* private-other-body */")
				}))
				defer other.Close()
				cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					record("cdn:", r)
					if !tc.allow {
						t.Error("external asset contacted without allowlist")
					}
					w.Header().Set("Server", "Apache")
					w.Header().Set("X-Powered-By", "Express")
					http.SetCookie(w, &http.Cookie{Name: "private-asset-cookie", Value: "private-cookie"})
					switch r.URL.Path {
					case "/react.js":
						w.Header().Set("Content-Type", "text/javascript")
						if tc.wrongMIME {
							w.Header().Set("Content-Type", "text/plain")
						}
						if tc.gzip {
							w.Header().Set("Content-Encoding", "gzip")
							gz := gzip.NewWriter(w)
							if _, err := gz.Write(js); err != nil {
								t.Error(err)
							}
							if err := gz.Close(); err != nil {
								t.Error(err)
							}
						} else {
							w.Write(js)
						}
					case "/bootstrap.css":
						w.Header().Set("Content-Type", "text/css")
						w.Write(css)
					case "/redirect.js":
						w.Header().Set("Location", other.URL+"/redirect-destination?private-location")
						w.WriteHeader(http.StatusFound)
					case "/missing.js":
						w.WriteHeader(http.StatusNotFound)
					default:
						t.Errorf("unselected asset or nested discovery: %s", r.URL)
					}
				}))
				defer cdn.Close()
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					record("page:", r)
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Location", "/page?private-page")
						w.WriteHeader(http.StatusFound)
						fmt.Fprintf(w, `<script src="%s/hop-only.js"></script>`, cdn.URL)
					case "/page":
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Server", "nginx")
						http.SetCookie(w, &http.Cookie{Name: "private-page-cookie", Value: "private-cookie"})
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprintf(w, `<script src="%[1]s/react.js?private-js"></script><script src="/local.js?private-local"></script><link rel=stylesheet href="%[1]s/bootstrap.css?private-css"><script src="%[2]s/other.js?private-other"></script><script src="%[1]s/react.js?private-js#duplicate"></script>`, cdn.URL, other.URL)
						if tc.bounded {
							fmt.Fprintf(w, `<script src="%[1]s/redirect.js"></script><script src="%[1]s/missing.js"></script><script src="%[1]s/sixth.js"></script>`, cdn.URL)
						}
					case "/local.js":
						w.Header().Set("Content-Type", "text/javascript")
						fmt.Fprint(w, "/* private-local-body */")
					default:
						t.Errorf("unexpected page request: %s", r.URL)
					}
				}))
				defer server.Close()
				args := []string{"--redact-query"}
				allowed := []string{}
				if tc.assets {
					args = append(args, "--assets")
				}
				if tc.allow {
					args = append(args, "--asset-origin", cdn.URL)
					allowed = append(allowed, cdn.URL)
				}
				if tc.duplicate {
					args = append(args, "--asset-origin="+cdn.URL+"/")
				}
				if tc.second {
					args = append(args, "--asset-origin", other.URL)
					allowed = append(allowed, other.URL)
				}
				if tc.gzip {
					args = append(args, "--prefer-html")
				}
				if format == "json" {
					args = append(args, "--json")
				} else if format == "color" {
					args = append(args, "--color=always")
				} else {
					args = append(args, "--no-color")
				}
				var stdout, stderr bytes.Buffer
				if code := cli.Run(append(args, server.URL+"/start?private-start"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("exit=%d stderr=%s", code, &stderr)
				}
				wantRequests := []string{"page:/start", "page:/page"}
				if tc.assets {
					if tc.allow {
						wantRequests = append(wantRequests, "cdn:/react.js")
					}
					wantRequests = append(wantRequests, "page:/local.js")
					if tc.allow {
						wantRequests = append(wantRequests, "cdn:/bootstrap.css")
					}
					if tc.second {
						wantRequests = append(wantRequests, "other:/other.js")
					}
					if tc.bounded {
						wantRequests = append(wantRequests, "cdn:/redirect.js", "cdn:/missing.js")
					}
				}
				mu.Lock()
				gotRequests := append([]string{}, visited...)
				mu.Unlock()
				if !reflect.DeepEqual(gotRequests, wantRequests) {
					t.Fatalf("requests=%v want=%v", gotRequests, wantRequests)
				}
				if strings.Contains(stdout.String(), "private-") || strings.Contains(stdout.String(), "Apache") || strings.Contains(stdout.String(), "Express") {
					t.Fatalf("response data leaked or asset headers supplied page evidence: %s", &stdout)
				}
				ids := []string{"nginx"}
				if tc.allow {
					ids = []string{"bootstrap", "nginx"}
					if !tc.wrongMIME {
						ids = append(ids, "react")
					}
				}
				if format != "json" {
					for _, id := range ids {
						name := map[string]string{"nginx": "nginx [web server]", "bootstrap": "Bootstrap [UI framework]", "react": "React [JavaScript framework]"}[id]
						if !strings.Contains(stdout.String(), name) {
							t.Errorf("missing %s", name)
						}
					}
					if strings.Contains(stdout.String(), "Allowed asset origins (configured; references only):") != tc.allow {
						t.Error("configured scope heading mismatch")
					}
					if tc.allow && (!strings.Contains(stdout.String(), "direct same-origin and allowed-origin scope") || !strings.Contains(stdout.String(), cdn.URL+"\n")) {
						t.Error("missing allowed origin/scope")
					}
					if tc.assets && !tc.second && !strings.Contains(stdout.String(), other.URL+" (scripts: 1, stylesheets: 0)") {
						t.Error("remaining excluded origin missing")
					}
					if !tc.allow && strings.Contains(stdout.String(), "Bootstrap [UI framework]") {
						t.Error("uncollected external CSS identified")
					}
					if (!tc.allow || tc.wrongMIME) && strings.Contains(stdout.String(), "React [JavaScript framework]") {
						t.Error("unaccepted external JS identified")
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				gotIDs := []string{}
				for _, f := range report.Findings {
					gotIDs = append(gotIDs, f.ID)
					if f.ID != "nginx" {
						path, rule := "/react.js", "asset-client-runtime"
						if f.ID == "bootstrap" {
							path, rule = "/bootstrap.css", "asset-css-banner-and-buttons"
						}
						if f.State != "inferred" || len(f.Evidence) != 1 || f.Evidence[0].RuleID != rule || f.Evidence[0].AssetURL != cdn.URL+path+"?[redacted]" {
							t.Errorf("invalid external provenance: %+v", f)
						}
					}
				}
				if report.SchemaVersion != 1 || report.ResponseScope != "http_error_response" || !reflect.DeepEqual(gotIDs, ids) || (report.Assets != nil) != tc.assets {
					t.Fatalf("report=%+v", report)
				}
				if !tc.assets {
					return
				}
				a := report.Assets
				excluded := []output.ExternalOrigin{}
				if !tc.allow {
					excluded = append(excluded, output.ExternalOrigin{Origin: cdn.URL, Scripts: 2, Stylesheets: 1})
				}
				if !tc.second {
					excluded = append(excluded, output.ExternalOrigin{Origin: other.URL, Scripts: 1})
				}
				status, reason, collected := "complete", "", len(wantRequests)-2
				if tc.wrongMIME {
					status, reason, collected = "incomplete", "asset_failures_or_skips", collected-1
				}
				if tc.bounded {
					status, reason, collected = "incomplete", "reference_limit", collected-2
				}
				duplicates := 0
				if tc.allow {
					duplicates = 1
				}
				if a.Status != status || a.Reason != reason || a.Attempted != len(wantRequests)-2 || a.Collected != collected || a.Truncated != tc.bounded || a.Duplicates != duplicates || a.ExternalOriginsTruncated || !reflect.DeepEqual(a.AllowedOrigins, allowed) || !reflect.DeepEqual(a.ExternalOrigins, excluded) {
					t.Fatalf("assets=%+v", a)
				}
				if tc.wrongMIME && a.Items[0].Reason != "unsuitable_content_type" {
					t.Error("JS MIME gate was relaxed")
				}
				if tc.bounded && (a.Items[3].Reason != "redirect_not_allowed" || a.Items[4].Reason != "unsuccessful_status") {
					t.Error("optional status/redirect policy changed")
				}
			})
		}
	}
}

func TestCLIAllowedOriginPreservesTLSVerification(t *testing.T) {
	external := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("untrusted TLS asset reached HTTP handler") }))
	external.Config.ErrorLog = log.New(io.Discard, "", 0)
	external.StartTLS()
	defer external.Close()
	page := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Server", "nginx")
		fmt.Fprintf(w, `<script src="%s/private-path.js?private-query"></script>`, external.URL)
	}))
	defer page.Close()
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"--assets", "--asset-origin", external.URL, "--json", "--redact-query", page.URL}, &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%s", code, &stderr)
	}
	var report output.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Assets == nil || report.Assets.Status != "incomplete" || report.Assets.Attempted != 1 || report.Assets.Collected != 0 || len(report.Findings) != 1 || report.Findings[0].ID != "nginx" || report.Assets.Items[0].Reason != "request_or_body_error" || strings.Contains(stdout.String(), "private-query") {
		t.Fatalf("TLS policy/report=%+v", report)
	}
}

func TestCLIAllowedOriginCannotDowngradeHTTPSPage(t *testing.T) {
	external := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { t.Error("HTTPS page caused HTTP asset request") }))
	defer external.Close()
	page := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/secure.js" {
			w.Header().Set("Content-Type", "text/javascript")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<script src="%s/plain.js"></script><script src="/secure.js"></script>`, external.URL)
	}))
	defer page.Close()
	// Trust the local page certificate; keep TLS verification enabled.
	original := http.DefaultTransport
	transport := page.Client().Transport.(*http.Transport).Clone()
	http.DefaultTransport = transport
	defer func() { http.DefaultTransport = original; transport.CloseIdleConnections() }()
	var stdout, stderr bytes.Buffer
	if code := cli.Run([]string{"--assets", "--asset-origin", external.URL, "--allow-http-downgrade", "--json", page.URL}, &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
		t.Fatalf("code=%d stderr=%s", code, &stderr)
	}
	var report output.Report
	if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	a := report.Assets
	if a == nil || a.Attempted != 1 || a.Collected != 1 || len(a.Items) != 1 || a.Items[0].URL != page.URL+"/secure.js" || !reflect.DeepEqual(a.AllowedOrigins, []string{external.URL}) || !reflect.DeepEqual(a.ExternalOrigins, []output.ExternalOrigin{{Origin: external.URL, Scripts: 1}}) {
		t.Fatalf("downgrade scope=%+v", a)
	}
}
