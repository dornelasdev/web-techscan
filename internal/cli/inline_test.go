package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"

	"webscan/internal/assets"
	"webscan/internal/cli"
	"webscan/internal/output"
)

func TestCLIInlineCSS(t *testing.T) {
	fixtures := map[string]string{}
	for _, file := range []string{"bootstrap-5.3.min.css", "tailwind-3.4.css", "tailwind-4.1.min.css"} {
		data, err := os.ReadFile("../detect/testdata/coverage/" + file)
		if err != nil {
			t.Fatal(err)
		}
		fixtures[file] = string(data)
	}
	b, tw3, tw4 := fixtures["bootstrap-5.3.min.css"], fixtures["tailwind-3.4.css"], fixtures["tailwind-4.1.min.css"]
	full := b + tw3 + tw4 + `/* private-inline-body */ @import "https://ignored.test/private-import.css";`
	var prefixes, rest string
	for _, css := range []string{b, tw3, tw4} {
		start := strings.Index(css, "/*!")
		if start < 0 {
			t.Fatal("fixture lacks banner")
		}
		end := strings.Index(css[start:], "*/")
		if end < 0 {
			t.Fatal("fixture lacks closed banner")
		}
		// Authored fixtures have an introductory comment before the actual
		// technology banner. Split after that banner, not the first comment.
		cut := start + end + 2
		prefixes += css[:cut]
		rest += css[cut:]
	}
	for _, tc := range []struct {
		name, kind, typ, reason    string
		enabled, want, asset, fail bool
		seen, collected            int
	}{
		{name: "default-off", kind: "active"},
		{name: "active", kind: "active", enabled: true, want: true, seen: 1, collected: 1},
		{name: "asset-and-inline", kind: "active", enabled: true, want: true, asset: true, seen: 1, collected: 1},
		{name: "asset-failure-keeps-inline", kind: "active", enabled: true, want: true, asset: true, fail: true, seen: 1, collected: 1},
		{name: "template", kind: "template", enabled: true},
		{name: "unsupported-style-type", kind: "unsupported", enabled: true},
		{name: "attribute", kind: "attribute", enabled: true},
		{name: "script-string", kind: "script", enabled: true},
		{name: "split-blocks", kind: "split", enabled: true, seen: 2, collected: 2},
		{name: "split-inline-and-asset", kind: "split-asset", enabled: true, asset: true, seen: 1, collected: 1},
		{name: "redirect-only", kind: "redirect", enabled: true},
		{name: "non-html", kind: "active", enabled: true, typ: "text/plain", reason: "unsupported_page_type"},
		{name: "xhtml", kind: "active", enabled: true, typ: "application/xhtml+xml", reason: "unsupported_page_type"},
		{name: "oversized-prefix", kind: "oversized", enabled: true, seen: 2, collected: 1, reason: "block_byte_limit"},
		{name: "oversized-then-valid", kind: "oversized-then-valid", enabled: true, want: true, seen: 2, collected: 1, reason: "block_byte_limit"},
		{name: "count-limit", kind: "count", enabled: true, seen: 21, collected: 20, reason: "block_limit"},
		{name: "aggregate-limit", kind: "aggregate", enabled: true, seen: 3, collected: 2, reason: "total_byte_limit"},
	} {
		formats := []string{"json", "plain", "color"}
		if strings.HasPrefix(tc.kind, "oversized") || tc.kind == "aggregate" {
			formats = []string{"json"}
		}
		for _, format := range formats {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				body := "<style>" + full + "</style>"
				switch tc.kind {
				case "template":
					body = "<template>" + body + "</template>"
				case "unsupported":
					body = `<style type="text/plain">` + full + "</style>"
				case "attribute":
					body = `<div style="` + html.EscapeString(full) + `">fixture</div>`
				case "script":
					body = "<script>const css = '<style>" + full + "</style>';</script>"
				case "split":
					body = "<style>" + prefixes + "</style><style>" + rest + "</style>"
				case "split-asset":
					body = "<style>" + prefixes + "</style>"
				case "redirect":
					body = "<p>final page</p>"
				case "oversized", "oversized-then-valid":
					big := full + "/*" + strings.Repeat("0", int(assets.MaxInlineStyleBytes)+1-len(full)-4) + "*/"
					body = "<style>" + big + "</style><style>.fixture{}</style>"
					if tc.kind == "oversized-then-valid" {
						body = "<style>" + big + "</style><style>" + full + "</style>"
					}
				case "count":
					body = strings.Repeat("<style></style>", assets.MaxInlineStyleBlocks) + body
				case "aggregate":
					big := "/*" + strings.Repeat("0", int(assets.MaxInlineStyleBytes)-4) + "*/"
					body = "<style>" + big + "</style><style>" + big + "</style>" + body
				}
				if tc.asset {
					body += `<link rel=stylesheet href="/styles.css?private-asset">`
				}
				var mu sync.Mutex
				requests := []string{}
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					requests = append(requests, r.URL.Path)
					mu.Unlock()
					if r.Method != "GET" || r.UserAgent() != "webscan" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || (r.URL.Path == "/styles.css" && r.Referer() != "") {
						t.Errorf("request policy=%s %v", r.Method, r.Header)
					}
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Location", "/page?private-page")
						w.WriteHeader(http.StatusFound)
						fmt.Fprint(w, "<style>"+full+"</style>")
					case "/page":
						typ := tc.typ
						if typ == "" {
							typ = "text/html"
						}
						w.Header().Set("Content-Type", typ)
						w.Header().Set("Server", "nginx")
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, body)
					case "/styles.css":
						w.Header().Set("Content-Type", "text/css")
						w.Header().Set("Server", "Apache")
						if tc.fail {
							w.WriteHeader(http.StatusNotFound)
						}
						if tc.kind == "split-asset" {
							fmt.Fprint(w, rest)
						} else {
							fmt.Fprint(w, full)
						}
					default:
						t.Errorf("unexpected request or inline import: %s", r.URL)
					}
				}))
				defer server.Close()
				args := []string{"--redact-query"}
				if tc.enabled {
					args = append(args, "--assets")
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
					t.Fatalf("code=%d stderr=%s", code, &stderr)
				}
				wantRequests := []string{"/start", "/page"}
				if tc.asset {
					wantRequests = append(wantRequests, "/styles.css")
				}
				mu.Lock()
				gotRequests := append([]string{}, requests...)
				mu.Unlock()
				if !reflect.DeepEqual(gotRequests, wantRequests) {
					t.Fatalf("requests=%v want=%v", gotRequests, wantRequests)
				}
				for _, raw := range []string{"private-", "--bs-btn-", "--tw-translate-x", "ignored.test", "getbootstrap.com", "tailwindcss.com", "Apache"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw CSS/header leaked: %q", raw)
					}
				}
				if format != "json" {
					for _, name := range []string{"Bootstrap [UI framework]", "Tailwind CSS [UI framework]"} {
						if strings.Contains(stdout.String(), name) != tc.want {
							t.Errorf("unexpected %s: %s", name, &stdout)
						}
					}
					if strings.Contains(stdout.String(), "Inline style block: 1") != tc.want || strings.Contains(stdout.String(), "Inline CSS:") != tc.enabled {
						t.Fatalf("inline terminal provenance/scope=%s", &stdout)
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				ids := []string{}
				for _, finding := range report.Findings {
					ids = append(ids, finding.ID)
					if finding.ID == "nginx" {
						continue
					}
					rules := []string{"inline-css-banner-and-buttons"}
					if finding.ID == "tailwindcss" {
						rules = []string{"inline-css-v3-banner-and-preflight", "inline-css-v4-banner-and-translate"}
					}
					if tc.asset && !tc.fail {
						assetRules := make([]string, len(rules))
						for i, rule := range rules {
							assetRules[i] = strings.Replace(rule, "inline-css-", "asset-css-", 1)
						}
						rules = append(assetRules, rules...)
					}
					if finding.State != "inferred" || len(finding.Evidence) != len(rules) {
						t.Fatalf("finding=%+v", finding)
					}
					for i, evidence := range finding.Evidence {
						source, url, block := "inline_css", "", 1
						if tc.kind == "oversized-then-valid" {
							block = 2
						}
						if strings.HasPrefix(rules[i], "asset-") {
							source, url, block = "asset_css", server.URL+"/styles.css?[redacted]", 0
						}
						if evidence.RuleID != rules[i] || evidence.AssetURL != url || evidence.StyleBlock != block {
							t.Fatalf("evidence=%+v", evidence)
						}
						for _, signal := range evidence.Signals {
							if signal.Source != source {
								t.Fatalf("source=%+v", signal)
							}
						}
					}
				}
				wantIDs := []string{"nginx"}
				if tc.want {
					wantIDs = []string{"bootstrap", "nginx", "tailwindcss"}
				}
				if !reflect.DeepEqual(ids, wantIDs) || report.ResponseScope != "http_error_response" || (report.Assets != nil) != tc.enabled {
					t.Fatalf("report=%+v", report)
				}
				if !tc.enabled {
					return
				}
				a := report.Assets
				inline := a.InlineCSS
				status := "complete"
				if tc.reason != "" {
					status = "incomplete"
				}
				if tc.typ != "" {
					status = "skipped"
				}
				if inline.Status != status || inline.Reason != tc.reason || inline.Seen != tc.seen || inline.Collected != tc.collected || inline.Skipped != tc.seen-tc.collected || inline.Truncated != (tc.kind == "count") || inline.MaxBlocks != 20 || inline.MaxBlockBytes != 512<<10 || inline.MaxTotalBytes != 1<<20 || len(inline.Items) > 20 {
					t.Fatalf("inline metadata=%+v", inline)
				}
				networkStatus, attempted := "complete", 0
				if tc.asset {
					attempted = 1
				}
				if tc.fail {
					networkStatus = "incomplete"
				}
				if tc.typ != "" {
					networkStatus = "skipped"
				}
				if a.Status != networkStatus || a.Attempted != attempted {
					t.Fatalf("inline changed network accounting: %+v", a)
				}
			})
		}
	}
}
