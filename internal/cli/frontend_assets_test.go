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

func TestCLICombinedFrontendAssets(t *testing.T) {
	read := func(name string) string {
		t.Helper()
		body, err := os.ReadFile("../detect/testdata/coverage/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	css := read("bootstrap-5.3.min.css")
	react := read("react-19-client.min.js")
	vue := read("vue-3-renderer.min.js")
	// Valid marker text deliberately appears in the wrong asset kinds too.
	nextBody := buildManifestFixture + "\n" + react + "\n" + css
	vueBody := vue + "\n" + css
	cssBody := css + "\n/* " + buildManifestFixture + react + vue + " */"
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	nextPath, vuePath, cssPath := "/_next/static/runtime?private-react=1", "/_nuxt/runtime?private-vue=1", "/style?private-css=1"
	for _, scenario := range []struct {
		name                                                   string
		disabled, reverse, lateFailure, reactFailed, cssFailed bool
		nextHeader, nuxtHeader                                 bool
		vueReason                                              string
	}{
		{name: "complete"},
		{name: "default-off", disabled: true},
		{name: "reverse-order", reverse: true},
		{name: "next-header-upgrade", nextHeader: true},
		{name: "nuxt-header-upgrade", nuxtHeader: true},
		{name: "independent-header-upgrades", nextHeader: true, nuxtHeader: true},
		{name: "later-failure", lateFailure: true},
		{name: "react-failure-before-vue", reactFailed: true},
		{name: "vue-wrong-mime", vueReason: "unsuitable_content_type"},
		{name: "vue-truncated", vueReason: "request_or_body_error"},
		{name: "css-failure-after-js", cssFailed: true},
	} {
		for _, format := range []string{"json", "plain", "color"} {
			for _, redact := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s/%s/redact=%t", scenario.name, format, redact), func(t *testing.T) {
					refs := []string{nextPath, vuePath, cssPath}
					if scenario.reverse {
						refs = []string{cssPath, vuePath, nextPath}
					}
					if scenario.lateFailure {
						refs = append(refs, "/late?private-late=1")
					}
					var mu sync.Mutex
					var requests []string
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						requests = append(requests, r.RequestURI)
						mu.Unlock()
						if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "webscan" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
							t.Errorf("unexpected request method/UA/credentials: %s", r.RequestURI)
						}
						switch r.URL.Path {
						case "/start":
							w.Header().Set("X-Powered-By", "Express")
							w.Header().Set("Location", "/page?private-page=1")
							w.WriteHeader(http.StatusFound)
						case "/page":
							w.Header().Set("Content-Type", "text/html")
							w.Header().Set("Set-Cookie", "fixture=private-cookie-value; Path=/")
							if scenario.nextHeader {
								w.Header().Add("X-Powered-By", "Next.js")
							}
							if scenario.nuxtHeader {
								w.Header().Add("X-Powered-By", "Nuxt")
							}
							fmt.Fprintf(w, `<script id="__NEXT_DATA__" type="application/json">{}</script><script id="__NUXT_DATA__" type="application/json">[]</script><script>%s%s</script><style>%s</style>`, react, vue, css)
							for _, ref := range refs {
								if ref == cssPath {
									fmt.Fprintf(w, `<link rel="stylesheet" href="%s">`, ref)
								} else {
									fmt.Fprintf(w, `<script type="module" src="%s"></script>`, ref)
								}
							}
							fmt.Fprintf(w, `<link rel="stylesheet" href="%s#duplicate">`, cssPath)
						case "/_next/static/runtime", "/_nuxt/runtime", "/style", "/late":
							if r.Header.Get("Referer") != "" {
								t.Error("asset request included a referrer")
							}
							w.Header().Set("X-Powered-By", "Express")
							w.Header().Set("Server", "Apache")
							w.Header().Set("Content-Type", "text/javascript")
							switch r.URL.Path {
							case "/_next/static/runtime":
								if scenario.reactFailed {
									w.WriteHeader(http.StatusForbidden)
								}
								fmt.Fprint(w, nextBody)
							case "/_nuxt/runtime":
								if scenario.vueReason == "unsuitable_content_type" {
									w.Header().Set("Content-Type", "text/css")
								}
								if scenario.vueReason == "request_or_body_error" {
									w.Header().Set("Content-Length", fmt.Sprint(len(vueBody)+100))
								}
								fmt.Fprint(w, vueBody)
							case "/style":
								w.Header().Set("Content-Type", "text/css")
								if scenario.cssFailed {
									w.WriteHeader(http.StatusForbidden)
								}
								fmt.Fprint(w, cssBody)
							case "/late":
								w.WriteHeader(http.StatusForbidden)
								fmt.Fprint(w, nextBody+vueBody)
							}
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
						wantRequests = append(wantRequests, refs...)
					}
					mu.Lock()
					gotRequests := append([]string(nil), requests...)
					mu.Unlock()
					if !reflect.DeepEqual(gotRequests, wantRequests) {
						t.Errorf("requests=%v want=%v", gotRequests, wantRequests)
					}
					for _, secret := range []string{"private-cookie-value", "private-runtime-body", "private-vue-body", "private-body.js", "__CLIENT_INTERNALS", "__vue_app__", "--bs-btn-", "Express", "Apache"} {
						if strings.Contains(stdout.String(), secret) {
							t.Errorf("raw/other-response data leaked: %s", secret)
						}
					}
					if redact && strings.Contains(stdout.String(), "private-") {
						t.Fatal("query leaked into output")
					}
					url := func(path string) string {
						if redact {
							path, _, _ = strings.Cut(path, "?")
							path += "?[redacted]"
						}
						return server.URL + path
					}
					wantReact := !scenario.disabled && !scenario.reactFailed
					wantVue := !scenario.disabled && scenario.vueReason == ""
					wantCSS := !scenario.disabled && !scenario.cssFailed
					status, reason := "complete", ""
					if scenario.reactFailed || scenario.vueReason != "" || scenario.cssFailed || scenario.lateFailure {
						status, reason = "incomplete", "asset_failures_or_skips"
					}
					if format != "json" {
						text := strings.NewReplacer("\x1b[32m", "", "\x1b[33m", "", "\x1b[0m", "").Replace(stdout.String())
						for _, want := range []struct {
							name, category    string
							present, detected bool
						}{{"Bootstrap", "UI framework", wantCSS, false}, {"Next.js", "framework", true, scenario.nextHeader}, {"Nuxt", "framework", true, scenario.nuxtHeader}, {"React", "framework", wantReact, false}, {"Vue", "framework", wantVue, false}} {
							label := " " + want.name + " [" + want.category + "]"
							inferred := strings.Contains(text, "?"+label)
							detected := strings.Contains(text, "✓"+label)
							if (inferred || detected) != want.present || detected != (want.present && want.detected) || inferred != (want.present && !want.detected) {
								t.Errorf("unexpected %s state/presence: %s", want.name, text)
							}
						}
						for _, want := range []struct {
							path    string
							present bool
						}{{nextPath, wantReact}, {vuePath, wantVue}, {cssPath, wantCSS}} {
							if strings.Contains(text, "    Asset: "+url(want.path)+"\n") != want.present {
								t.Errorf("unexpected asset evidence for %s: %s", want.path, text)
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
					if report.SchemaVersion != 1 || report.HTTPStatus != http.StatusOK || report.ResponseScope != "final_response" || report.CatalogSize != engine.Len() || report.QueryRedacted != redact || report.URL != url(wantRequests[0]) || report.FinalURL != url(wantRequests[1]) || !reflect.DeepEqual(report.Redirects, []output.Redirect{{FromURL: url(wantRequests[0]), ToURL: url(wantRequests[1]), StatusCode: 302}}) {
						t.Fatalf("metadata=%+v", report)
					}
					type expectedEvidence struct {
						rule, url, source string
						count             int
					}
					want := map[string][]expectedEvidence{
						"nextjs": {{"pages-html-markers", "", "html", 2}},
						"nuxt":   {{"payload-html-markers", "", "html", 2}},
					}
					if wantCSS {
						want["bootstrap"] = []expectedEvidence{{"asset-css-banner-and-buttons", url(cssPath), "asset_css", 2}}
					}
					if wantReact {
						want["react"] = []expectedEvidence{{"asset-client-runtime", url(nextPath), "asset_javascript", 2}}
						want["nextjs"] = append([]expectedEvidence{{"asset-build-manifest", url(nextPath), "asset_javascript", 2}}, want["nextjs"]...)
					}
					if wantVue {
						want["vue"] = []expectedEvidence{{"asset-renderer-runtime", url(vuePath), "asset_javascript", 3}}
					}
					if scenario.nextHeader {
						want["nextjs"] = append(want["nextjs"], expectedEvidence{"powered-by-header", "", "header", 1})
					}
					if scenario.nuxtHeader {
						want["nuxt"] = append(want["nuxt"], expectedEvidence{"powered-by-header", "", "header", 1})
					}
					if len(report.Findings) != len(want) {
						t.Fatalf("findings=%+v want=%+v", report.Findings, want)
					}
					previous := ""
					for _, f := range report.Findings {
						expected, ok := want[f.ID]
						state, category := "inferred", "framework"
						if (f.ID == "nextjs" && scenario.nextHeader) || (f.ID == "nuxt" && scenario.nuxtHeader) {
							state = "detected"
						}
						if f.ID == "bootstrap" {
							category = "ui_framework"
						}
						if !ok || f.ID <= previous || f.State != state || f.Category != category || len(f.Evidence) != len(expected) {
							t.Fatalf("finding=%+v want=%+v", f, expected)
						}
						previous = f.ID
						for i, e := range f.Evidence {
							w := expected[i]
							if e.RuleID != w.rule || e.AssetURL != w.url || e.InferredFrom != "" || len(e.Signals) != w.count {
								t.Fatalf("evidence=%+v want=%+v", e, w)
							}
							for _, signal := range e.Signals {
								name := ""
								if w.source == "header" {
									name = "X-Powered-By"
								}
								if signal.Source != w.source || signal.Name != name {
									t.Errorf("signal=%+v want=%+v", signal, w)
								}
							}
						}
					}
					if scenario.disabled {
						if report.Assets != nil {
							t.Error("default gained asset report")
						}
						return
					}
					collected := 0
					for _, present := range []bool{wantReact, wantVue, wantCSS} {
						if present {
							collected++
						}
					}
					if report.Assets == nil || report.Assets.Status != status || report.Assets.Reason != reason || report.Assets.Collected != collected || report.Assets.Attempted != len(refs) || report.Assets.Duplicates != 1 || len(report.Assets.Items) != len(refs) {
						t.Fatalf("assets=%+v", report.Assets)
					}
					for i, item := range report.Assets.Items {
						wantStatus, wantReason := "collected", ""
						if (refs[i] == nextPath && scenario.reactFailed) || (refs[i] == cssPath && scenario.cssFailed) || strings.HasPrefix(refs[i], "/late?") {
							wantStatus, wantReason = "failed", "unsuccessful_status"
						}
						if refs[i] == vuePath && scenario.vueReason != "" {
							wantStatus, wantReason = "failed", scenario.vueReason
						}
						if item.URL != url(refs[i]) || item.Status != wantStatus || item.Reason != wantReason {
							t.Errorf("item=%+v", item)
						}
					}
				})
			}
		}
	}
}
