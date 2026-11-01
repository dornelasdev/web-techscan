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

	"webscan/internal/assets"
	"webscan/internal/cli"
	"webscan/internal/detect"
	"webscan/internal/output"
)

type libraryCSSAsset struct {
	path, body                   string
	stylesheet, external, failed bool
}

func TestCLICombinedLibrariesAndCSS(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		t.Helper()
		data, err := os.ReadFile("../detect/testdata/coverage/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	libraries := make(map[string]string)
	for id, file := range map[string]string{"jquery": "jquery-core.min.js", "lazysizes": "lazysizes-core.min.js", "modernizr": "modernizr-v2-core.min.js"} {
		// Remove the authored introductory comment so the same scaffold can
		// safely appear inside a CSS comment as a wrong-source decoy.
		_, code, ok := strings.Cut(read(file), "\n")
		if !ok {
			t.Fatalf("fixture lacks introductory line: %s", file)
		}
		libraries[id] = code
	}
	allJS := libraries["jquery"] + libraries["lazysizes"] + libraries["modernizr"]
	b, tw := read("bootstrap-5.3.min.css"), read("tailwind-3.4.css")
	css := b + tw + "/* " + allJS + " */"
	comment := func(size int) string { return "/*" + strings.Repeat("0", size-4) + "*/" }
	for _, kind := range []string{"shared", "separate-reversed", "allowed-origin", "js-failure", "css-failure", "late-failure", "reference-limit", "inline-byte-limit", "inline-count-limit", "inline-total-limit", "page-only"} {
		formats := []string{"json"}
		if kind == "shared" || kind == "late-failure" {
			formats = append(formats, "plain", "color")
		}
		for _, format := range formats {
			t.Run(kind+"/"+format, func(t *testing.T) {
				specs := []libraryCSSAsset{{path: "/bundle?private-js", body: allJS}, {path: "/styles?private-css", body: css, stylesheet: true}}
				jsPaths := map[string]string{"jquery": specs[0].path, "lazysizes": specs[0].path, "modernizr": specs[0].path}
				if kind == "separate-reversed" {
					specs = []libraryCSSAsset{{path: "/styles?private-css", body: css, stylesheet: true}}
					for _, id := range []string{"modernizr", "lazysizes", "jquery"} {
						jsPaths[id] = "/" + id + "?private-js"
						specs = append(specs, libraryCSSAsset{path: jsPaths[id], body: libraries[id]})
					}
				}
				switch kind {
				case "allowed-origin":
					specs[0].external = true
				case "js-failure":
					specs[0].failed = true
				case "css-failure":
					specs[1].failed = true
				case "late-failure":
					specs = append(specs, libraryCSSAsset{path: "/late?private-late", body: allJS, failed: true})
				case "reference-limit":
					// A failed attempt still consumes a slot. Modernizr exists
					// only in the sixth eligible asset and wrong-source decoys.
					specs[0].body = libraries["jquery"] + libraries["lazysizes"]
					jsPaths["modernizr"] = "/sixth?private-sixth"
					specs = append(specs,
						libraryCSSAsset{path: "/missing?private-failed", body: libraries["modernizr"], failed: true},
						libraryCSSAsset{path: "/filler-a", body: "void 0;"},
						libraryCSSAsset{path: "/filler-b", body: "void 0;"},
						libraryCSSAsset{path: jsPaths["modernizr"], body: libraries["modernizr"]})
				}
				blocks := []string{css}
				bBlock, twBlock := 1, 1
				wantInline := output.InlineCSSReport{Status: "complete", MaxBlocks: 20, MaxBlockBytes: 512 << 10, MaxTotalBytes: 1 << 20,
					Seen: 1, Collected: 1, Bytes: int64(len(css)), Items: []output.InlineStyleItem{{Index: 1, Status: "collected", Bytes: int64(len(css))}}}
				switch kind {
				case "inline-byte-limit":
					blocks = []string{css + comment(int(assets.MaxInlineStyleBytes)+1-len(css)), tw}
					bBlock, twBlock = 0, 2
					wantInline.Status, wantInline.Reason = "incomplete", "block_byte_limit"
					wantInline.Seen, wantInline.Collected, wantInline.Skipped, wantInline.Bytes = 2, 1, 1, int64(len(tw))
					wantInline.Items = []output.InlineStyleItem{{Index: 1, Status: "skipped", Reason: "block_byte_limit", Bytes: assets.MaxInlineStyleBytes + 1}, {Index: 2, Status: "collected", Bytes: int64(len(tw))}}
				case "inline-count-limit":
					blocks = append(make([]string, assets.MaxInlineStyleBlocks), css)
					bBlock, twBlock = 0, 0
					wantInline.Status, wantInline.Reason, wantInline.Truncated = "incomplete", "block_limit", true
					wantInline.Seen, wantInline.Collected, wantInline.Skipped, wantInline.Bytes = 21, 20, 1, 0
					wantInline.Items = make([]output.InlineStyleItem, 20)
					for i := range wantInline.Items {
						wantInline.Items[i] = output.InlineStyleItem{Index: i + 1, Status: "collected"}
					}
				case "inline-total-limit":
					blocks = []string{comment(int(assets.MaxInlineStyleBytes)), comment(int(assets.MaxInlineStyleBytes)), css}
					bBlock, twBlock = 0, 0
					wantInline.Status, wantInline.Reason = "incomplete", "total_byte_limit"
					wantInline.Seen, wantInline.Collected, wantInline.Skipped, wantInline.Bytes = 3, 2, 1, 1<<20
					wantInline.Items = []output.InlineStyleItem{{Index: 1, Status: "collected", Bytes: 512 << 10}, {Index: 2, Status: "collected", Bytes: 512 << 10}, {Index: 3, Status: "skipped", Reason: "total_byte_limit", Bytes: int64(len(css))}}
				}
				byPath := make(map[string]libraryCSSAsset)
				for _, spec := range specs {
					path, _, _ := strings.Cut(spec.path, "?")
					byPath[path] = spec
				}
				var mu sync.Mutex
				requests := []string{}
				record := func(prefix string, r *http.Request) {
					mu.Lock()
					requests = append(requests, prefix+r.RequestURI)
					mu.Unlock()
					wantReferer := ""
					if prefix == "page:" && r.URL.Path == "/page" {
						wantReferer = "http://" + r.Host + "/start?private-start"
					}
					if r.Method != http.MethodGet || r.UserAgent() != "webscan" || r.Referer() != wantReferer || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Accept") != "" {
						t.Errorf("request policy=%s %v", r.Method, r.Header)
					}
				}
				serveAsset := func(w http.ResponseWriter, r *http.Request, external bool) {
					spec, ok := byPath[r.URL.Path]
					if !ok || spec.external != external {
						t.Errorf("unexpected asset/origin: %s external=%t", r.RequestURI, external)
						w.WriteHeader(http.StatusNotFound)
						return
					}
					mime := "application/javascript"
					if spec.stylesheet {
						mime = "text/css"
					}
					w.Header().Set("Content-Type", mime)
					w.Header().Set("Server", "Apache")
					w.Header().Set("X-Powered-By", "Express")
					w.Header().Set("Set-Cookie", "asset=private-asset-cookie; Path=/")
					if spec.failed {
						w.WriteHeader(http.StatusForbidden)
					}
					fmt.Fprint(w, spec.body)
				}
				cdnURL := ""
				if kind == "allowed-origin" {
					cdn := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						record("cdn:", r)
						serveAsset(w, r, true)
					}))
					defer cdn.Close()
					cdnURL = cdn.URL
				}
				page := "<script>" + allJS + "</script>"
				for _, block := range blocks {
					page += "<style>" + block + "</style>"
				}
				for _, spec := range append(append([]libraryCSSAsset{}, specs...), specs[0]) {
					ref := spec.path
					if spec.external {
						ref = cdnURL + ref
					}
					if spec.stylesheet {
						page += `<link rel="stylesheet" href="` + ref + `">`
					} else {
						page += `<script src="` + ref + `"></script>`
					}
				}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					record("page:", r)
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Location", "/page?private-page")
						w.Header().Set("Server", "Apache")
						w.WriteHeader(http.StatusFound)
						fmt.Fprint(w, `<script src="/hop-only"></script>`)
					case "/page":
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Server", "nginx")
						w.Header().Set("Set-Cookie", "page=private-page-cookie; Path=/")
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, page)
					default:
						serveAsset(w, r, false)
					}
				}))
				defer server.Close()
				selected := specs
				if kind == "reference-limit" {
					selected = specs[:5]
				} else if kind == "page-only" {
					selected = nil
				}
				urlFor := func(spec libraryCSSAsset) string {
					origin := server.URL
					if spec.external {
						origin = cdnURL
					}
					path, _, query := strings.Cut(spec.path, "?")
					if query {
						path += "?[redacted]"
					}
					return origin + path
				}
				wantRequests := []string{"page:/start?private-start", "page:/page?private-page"}
				wantItems := []output.AssetItem{}
				collected, status, reason, usage := 0, "complete", "", int64(0)
				for _, spec := range selected {
					prefix, assetKind := "page:", "javascript"
					if spec.external {
						prefix = "cdn:"
					}
					if spec.stylesheet {
						assetKind = "stylesheet"
					}
					wantRequests = append(wantRequests, prefix+spec.path)
					item := output.AssetItem{URL: urlFor(spec), Kind: assetKind, Status: "collected", HTTPStatus: 200, DecodedBytes: int64(len(spec.body)), EncodedBytes: int64(len(spec.body))}
					if spec.failed {
						item.Status, item.Reason, item.HTTPStatus, item.DecodedBytes, item.EncodedBytes = "failed", "unsuccessful_status", 403, 0, 0
						status, reason = "incomplete", "asset_failures_or_skips"
					} else {
						collected++
						usage += int64(len(spec.body))
					}
					wantItems = append(wantItems, item)
				}
				if kind == "reference-limit" {
					status, reason = "incomplete", "reference_limit"
				}
				type expectedEvidence struct {
					rule, url, source string
					block             int
				}
				want := map[string][]expectedEvidence{"nginx": {{"server-header", "", "header", 0}}}
				if kind != "page-only" {
					if kind != "js-failure" {
						for _, id := range []string{"jquery", "lazysizes", "modernizr"} {
							if kind == "reference-limit" && id == "modernizr" {
								continue
							}
							path, _, _ := strings.Cut(jsPaths[id], "?")
							rule := "asset-core-runtime"
							if id == "modernizr" {
								rule = "asset-v2-core-runtime"
							}
							want[id] = []expectedEvidence{{rule, urlFor(byPath[path]), "asset_javascript", 0}}
						}
					}
					for _, id := range []string{"bootstrap", "tailwindcss"} {
						assetRule, inlineRule, block := "asset-css-banner-and-buttons", "inline-css-banner-and-buttons", bBlock
						if id == "tailwindcss" {
							assetRule, inlineRule, block = "asset-css-v3-banner-and-preflight", "inline-css-v3-banner-and-preflight", twBlock
						}
						if kind != "css-failure" {
							want[id] = append(want[id], expectedEvidence{assetRule, urlFor(byPath["/styles"]), "asset_css", 0})
						}
						if block > 0 {
							want[id] = append(want[id], expectedEvidence{inlineRule, "", "inline_css", block})
						}
					}
				}
				var ids []string
				for _, id := range []string{"bootstrap", "jquery", "lazysizes", "modernizr", "nginx", "tailwindcss"} {
					if _, ok := want[id]; ok {
						ids = append(ids, id)
					}
				}
				args := []string{"--redact-query"}
				if kind != "page-only" {
					args = append(args, "--assets")
				}
				if cdnURL != "" {
					args = append(args, "--asset-origin", cdnURL)
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
				mu.Lock()
				gotRequests := append([]string(nil), requests...)
				mu.Unlock()
				if !reflect.DeepEqual(gotRequests, wantRequests) {
					t.Fatalf("requests=%v want=%v", gotRequests, wantRequests)
				}
				for _, raw := range []string{"private-", "--bs-btn-", "--tw-content", "lazySizesConfig", "_domPrefixes", "Math.random", "Apache", "Express"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw response/query leaked: %q", raw)
					}
				}
				if format != "json" {
					var lines []string
					for _, line := range strings.Split(stdout.String(), "\n") {
						line = strings.NewReplacer("\x1b[32m", "", "\x1b[33m", "", "\x1b[0m", "").Replace(line)
						if (strings.HasPrefix(line, "? ") || strings.HasPrefix(line, "✓ ")) && strings.HasSuffix(line, "]") {
							lines = append(lines, line)
						}
					}
					wantLines := []string{"? Bootstrap [UI framework]", "? jQuery [JavaScript library]", "? lazySizes [JavaScript library]", "? Modernizr [JavaScript library]", "✓ nginx [web server]", "? Tailwind CSS [UI framework]"}
					if !reflect.DeepEqual(lines, wantLines) || !strings.Contains(stdout.String(), "Inline style block: 1") || !strings.Contains(stdout.String(), "Inline CSS: complete") {
						t.Fatalf("terminal=%s", &stdout)
					}
					for _, evidence := range want {
						for _, e := range evidence {
							if e.url != "" && !strings.Contains(stdout.String(), "Asset: "+e.url) {
								t.Errorf("missing asset provenance: %s", e.url)
							}
						}
					}
					if !strings.Contains(stdout.String(), "Assets: "+status) {
						t.Errorf("missing network collection status: %s", &stdout)
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || !report.QueryRedacted || report.HTTPStatus != 403 || report.ResponseScope != "http_error_response" || report.BodyBytes != len(page) || report.URL != server.URL+"/start?[redacted]" || report.FinalURL != server.URL+"/page?[redacted]" || len(report.Findings) != len(ids) || !reflect.DeepEqual(report.Redirects, []output.Redirect{{FromURL: server.URL + "/start?[redacted]", ToURL: server.URL + "/page?[redacted]", StatusCode: 302}}) {
					t.Fatalf("report=%+v", report)
				}
				for i, finding := range report.Findings {
					state, category := "inferred", "javascript_library"
					if finding.ID == "nginx" {
						state, category = "detected", "web_server"
					} else if finding.ID == "bootstrap" || finding.ID == "tailwindcss" {
						category = "ui_framework"
					}
					if finding.ID != ids[i] || finding.State != state || finding.Category != category || len(finding.Evidence) != len(want[finding.ID]) {
						t.Fatalf("finding=%+v want=%v", finding, want)
					}
					for j, e := range finding.Evidence {
						expected := want[finding.ID][j]
						signals := []output.Signal{{Source: expected.source}, {Source: expected.source}}
						if finding.ID == "nginx" {
							signals = []output.Signal{{Source: "header", Name: "Server"}}
						}
						if e.RuleID != expected.rule || e.AssetURL != expected.url || e.StyleBlock != expected.block || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, signals) {
							t.Fatalf("evidence=%+v want=%+v", e, expected)
						}
					}
				}
				if kind == "page-only" {
					if report.Assets != nil {
						t.Fatal("page-only scan included asset metadata")
					}
					return
				}
				allowed := []string{}
				if cdnURL != "" {
					allowed = append(allowed, cdnURL)
				}
				a := report.Assets
				if a == nil || a.Status != status || a.Reason != reason || a.Truncated != (kind == "reference-limit") || a.Attempted != len(selected) || a.Collected != collected || a.Duplicates != 1 || a.DecodedBytes != usage || a.EncodedBytes != usage || a.Budget.Profile != "standard" || !reflect.DeepEqual(a.Items, wantItems) || !reflect.DeepEqual(a.AllowedOrigins, allowed) || len(a.ExternalOrigins) != 0 || a.ExternalOriginsTruncated {
					t.Fatalf("network collection=%+v wantItems=%+v", a, wantItems)
				}
				if !reflect.DeepEqual(a.InlineCSS, wantInline) {
					t.Fatalf("inline collection=%+v want=%+v", a.InlineCSS, wantInline)
				}
			})
		}
	}
}
