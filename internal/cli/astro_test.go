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

func TestCLIAstroHTML(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	read := func(file string) string {
		t.Helper()
		b, err := os.ReadFile("../detect/testdata/coverage/" + file)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	generator, island, legacy := read("astro-generator.html"), read("astro-island.html"), read("astro-island-legacy.html")
	js, css := read("jquery-core.min.js"), read("tailwind-3.4.css")
	valid := generator + island
	const empty = `<p>Example content.</p>`
	for _, tc := range []struct {
		name, body, mime, hop string
		status                int
		assets, failJS        bool
		rules                 []string
	}{
		{name: "generator-default", body: generator, rules: []string{"generator-meta"}},
		{name: "island-default", body: island, rules: []string{"hydration-island-html"}},
		{name: "legacy-island", body: legacy, rules: []string{"hydration-island-html"}},
		{name: "both-with-assets", body: valid, assets: true, rules: []string{"generator-meta", "hydration-island-html"}},
		{name: "duplicate-markup", body: valid + valid, rules: []string{"generator-meta", "hydration-island-html"}},
		{name: "xhtml", body: island, mime: "application/xhtml+xml", rules: []string{"hydration-island-html"}},
		{name: "error-page", body: valid, status: 403, rules: []string{"generator-meta", "hydration-island-html"}},
		{name: "non-html", body: valid, mime: "text/plain", assets: true},
		{name: "no-markers", body: empty},
		{name: "redirect-final", hop: empty, body: generator, rules: []string{"generator-meta"}},
		{name: "redirect-only", hop: valid, body: empty},
		{name: "split-hop", hop: `<meta name="generator"><astro-island uid="example" component-url="/widget">`, body: `<meta content="Astro v5.0.0"><astro-island renderer-url="/renderer" ssr client="load">`},
		{name: "asset-decoys-only", body: empty, assets: true},
		{name: "partial-page-with-asset-decoys", body: `<meta name="generator"><astro-island uid="example" component-url="/widget">`, assets: true},
		{name: "asset-failure-keeps-page", body: valid, assets: true, failJS: true, rules: []string{"generator-meta", "hydration-island-html"}},
	} {
		if tc.mime == "" {
			tc.mime = "text/html"
		}
		if tc.status == 0 {
			tc.status = 200
		}
		for _, format := range []string{"json", "plain", "color"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				body := tc.body + `<script src="/script?private-js=1"></script><link rel="stylesheet" href="/style?private-css=1">`
				var mu sync.Mutex
				var requests []string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					requests = append(requests, r.RequestURI)
					mu.Unlock()
					wantReferer := ""
					if r.URL.Path == "/page" && tc.hop != "" {
						wantReferer = "http://" + r.Host + "/start?private-start=1"
					}
					if r.Method != http.MethodGet || r.UserAgent() != "webscan" || r.Header.Get("Accept") != "" || r.Header.Get("Referer") != wantReferer || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
						t.Errorf("request=%s %+v", r.Method, r.Header)
					}
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("X-Powered-By", "Express")
						w.Header().Set("Location", "/page?private-page=1")
						w.WriteHeader(http.StatusFound)
						fmt.Fprint(w, tc.hop)
					case "/page":
						w.Header().Set("Content-Type", tc.mime)
						w.Header().Set("Server", "nginx")
						w.Header().Set("X-Generator", "Astro v5.0.0") // Not a supported Astro source.
						w.Header().Set("Set-Cookie", "fixture=private-page-cookie; Path=/")
						w.WriteHeader(tc.status)
						fmt.Fprint(w, body)
					case "/script":
						w.Header().Set("Content-Type", "text/javascript")
						w.Header().Set("X-Powered-By", "Express")
						w.Header().Set("Set-Cookie", "asset=private-asset-cookie; Path=/")
						if tc.failJS {
							w.WriteHeader(http.StatusForbidden)
						}
						fmt.Fprint(w, js+valid+"/* private-js-body */")
					case "/style":
						w.Header().Set("Content-Type", "text/css")
						fmt.Fprint(w, css+valid+"/* private-css-body */")
					default:
						t.Errorf("unexpected fetch: %s", r.RequestURI)
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer server.Close()
				args := []string{"--redact-query"}
				if tc.assets {
					args = append(args, "--assets")
				}
				switch format {
				case "json":
					args = append(args, "--json")
				case "color":
					args = append(args, "--color=always")
				default:
					args = append(args, "--no-color")
				}
				path := "/page?private-page=1"
				wantRequests := []string{path}
				if tc.hop != "" {
					path = "/start?private-start=1"
					wantRequests = append([]string{path}, wantRequests...)
				}
				collect := tc.assets && tc.mime == "text/html"
				if collect {
					wantRequests = append(wantRequests, "/script?private-js=1", "/style?private-css=1")
				}
				var stdout, stderr bytes.Buffer
				if code := cli.Run(append(args, server.URL+path), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("code=%d stderr=%s", code, &stderr)
				}
				mu.Lock()
				gotRequests := append([]string(nil), requests...)
				mu.Unlock()
				if !reflect.DeepEqual(gotRequests, wantRequests) {
					t.Errorf("requests=%v want=%v", gotRequests, wantRequests)
				}
				for _, raw := range []string{"private-page", "private-start", "private-js", "private-css", "private-component", "private-page-cookie", "private-asset-cookie", "astro-island", "component-url", "Astro v", "Express"} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw/private/borrowed data in output: %s", raw)
					}
				}
				wantJQuery, wantTailwind := collect && !tc.failJS, collect
				if format != "json" {
					marker := "?"
					if format == "color" {
						marker = "\x1b[33m?\x1b[0m"
					}
					wantCount := 0
					if len(tc.rules) > 0 {
						wantCount = 1
					}
					if strings.Count(stdout.String(), " Astro [framework]") != wantCount || strings.Contains(stdout.String(), marker+" Astro [framework]") != (wantCount == 1) || !strings.Contains(stdout.String(), "nginx [web server]") || strings.Contains(stdout.String(), "jQuery [JavaScript library]") != wantJQuery || strings.Contains(stdout.String(), "Tailwind CSS [UI framework]") != wantTailwind {
						t.Fatalf("output=%s", &stdout)
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				ids := []string{}
				if len(tc.rules) > 0 {
					ids = append(ids, "astro")
				}
				if wantJQuery {
					ids = append(ids, "jquery")
				}
				ids = append(ids, "nginx")
				if wantTailwind {
					ids = append(ids, "tailwindcss")
				}
				var gotIDs []string
				for _, f := range report.Findings {
					gotIDs = append(gotIDs, f.ID)
				}
				scope := "final_response"
				if tc.status >= 400 {
					scope = "http_error_response"
				}
				redirects := []output.Redirect{}
				if tc.hop != "" {
					redirects = append(redirects, output.Redirect{FromURL: server.URL + "/start?[redacted]", ToURL: server.URL + "/page?[redacted]", StatusCode: 302})
				}
				safePath := "/page?[redacted]"
				if tc.hop != "" {
					safePath = "/start?[redacted]"
				}
				if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || !report.QueryRedacted || report.URL != server.URL+safePath || report.FinalURL != server.URL+"/page?[redacted]" || report.HTTPStatus != tc.status || report.ResponseScope != scope || report.BodyBytes != len(body) || !reflect.DeepEqual(report.Redirects, redirects) || !reflect.DeepEqual(gotIDs, ids) {
					t.Fatalf("report=%+v", report)
				}
				for _, f := range report.Findings {
					if f.ID == "nginx" {
						if f.State != "detected" {
							t.Errorf("nginx=%+v", f)
						}
						continue
					}
					if f.State != "inferred" {
						t.Errorf("finding=%+v", f)
					}
					if f.ID != "astro" {
						continue
					}
					if f.Name != "Astro" || f.Category != "framework" || len(f.Evidence) != len(tc.rules) {
						t.Fatalf("Astro=%+v", f)
					}
					for i, e := range f.Evidence {
						if e.RuleID != tc.rules[i] || e.AssetURL != "" || e.StyleBlock != 0 || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []output.Signal{{Source: "html"}}) {
							t.Errorf("evidence=%+v", e)
						}
					}
				}
				if !tc.assets {
					if report.Assets != nil {
						t.Error("unexpected asset collection")
					}
					return
				}
				status, attempted, collected := "skipped", 0, 0
				if collect {
					status, attempted, collected = "complete", 2, 2
					if tc.failJS {
						status, collected = "incomplete", 1
					}
				}
				if report.Assets == nil || report.Assets.Status != status || report.Assets.Attempted != attempted || report.Assets.Collected != collected || len(report.Assets.Items) != attempted {
					t.Fatalf("assets=%+v", report.Assets)
				}
				if tc.failJS && report.Assets.Items[0].Reason != "unsuccessful_status" {
					t.Errorf("failed asset=%+v", report.Assets.Items[0])
				}
			})
		}
	}
}
