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

func TestCLIShadcnSidebar(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	read := func(file string) string {
		t.Helper()
		body, err := os.ReadFile("../detect/testdata/coverage/" + file)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	valid, js, css := read("shadcn-sidebar.html"), read("radix-popover.js"), read("tailwind-3.4.css")
	const wrapper = `<div data-slot="sidebar-wrapper" style="--sidebar-width:16rem;--sidebar-width-icon:3rem">`
	const innerMenu = `<div data-slot="sidebar-inner" data-sidebar="sidebar"><ul data-slot="sidebar-menu" data-sidebar="menu">`
	for _, tc := range []struct {
		name, body, mime, hop        string
		status                       int
		want, assets, failJS, prefer bool
	}{
		{name: "paired", body: valid, want: true},
		{name: "xhtml", body: valid, mime: "application/xhtml+xml", want: true},
		{name: "duplicate-pairs", body: valid + valid, want: true},
		{name: "error-page", body: valid, status: 403, want: true},
		{name: "generic-error", body: "Forbidden", status: 403},
		{name: "wrapper-only", body: wrapper},
		{name: "inner-menu-only", body: innerMenu},
		{name: "generic-components", body: `<button data-slot="button">Example</button><div data-slot="card"></div>`},
		{name: "non-html", body: valid, mime: "text/plain"},
		{name: "non-html-skips-assets", body: valid, mime: "text/plain", assets: true},
		{name: "redirect-to-pair", body: valid, hop: "<p>hop</p>", want: true},
		{name: "redirect-only", body: "<p>empty</p>", hop: valid},
		{name: "split-hop", body: innerMenu, hop: wrapper},
		{name: "paired-with-assets", body: valid, want: true, assets: true},
		{name: "partial-page-with-asset-decoys", body: innerMenu, assets: true, prefer: true},
		{name: "radix-and-tailwind-only", body: "<p>empty</p>", assets: true},
		{name: "late-css-keeps-page-after-js-failure", body: valid, want: true, assets: true, failJS: true},
		{name: "negotiated-pair", body: valid, want: true, prefer: true},
	} {
		if tc.mime == "" {
			tc.mime = "text/html"
		}
		if tc.status == 0 {
			tc.status = 200
		}
		for _, format := range []string{"json", "plain", "color"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				var mu sync.Mutex
				var requests []string
				body := tc.body + `<script src="/runtime?private-js=1"></script><script src="/runtime?private-js=1#duplicate"></script><link rel="stylesheet" href="/styles?private-css=1">`
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					mu.Lock()
					requests = append(requests, r.RequestURI)
					mu.Unlock()
					wantAccept := ""
					if tc.prefer && (r.URL.Path == "/start" || r.URL.Path == "/page") {
						wantAccept = "text/html, application/xhtml+xml;q=0.9, */*;q=0.8"
					}
					if r.Method != http.MethodGet || r.Header.Get("User-Agent") != "webscan" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" || r.Header.Get("Accept") != wantAccept || (r.URL.Path != "/page" && r.Header.Get("Referer") != "") {
						t.Errorf("request=%s %+v", r.Method, r.Header)
					}
					switch r.URL.Path {
					case "/start":
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("X-Powered-By", "Express")
						w.Header().Set("Set-Cookie", "hop=private-hop-cookie; Path=/")
						w.Header().Set("Location", "/page?private-page=1")
						w.WriteHeader(http.StatusFound)
						fmt.Fprint(w, tc.hop)
					case "/page":
						w.Header().Set("Content-Type", tc.mime)
						w.Header().Set("Server", "nginx")
						w.Header().Set("X-Marker", wrapper+innerMenu)
						w.Header().Set("Set-Cookie", "sidebar_state=private-page-cookie; Path=/")
						w.WriteHeader(tc.status)
						fmt.Fprint(w, body)
					case "/runtime":
						w.Header().Set("Content-Type", "text/javascript")
						w.Header().Set("X-Powered-By", "Express")
						w.Header().Set("Set-Cookie", "asset=private-asset-cookie; Path=/")
						if tc.failJS {
							w.WriteHeader(http.StatusForbidden)
						}
						fmt.Fprint(w, js+valid+"/* private-js-body */")
					case "/styles":
						w.Header().Set("Content-Type", "text/css")
						fmt.Fprint(w, css+valid+"/* private-css-body */")
					default:
						t.Errorf("unexpected request: %s", r.RequestURI)
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer server.Close()
				args := []string{"--redact-query"}
				if tc.assets {
					args = append(args, "--assets")
				}
				if tc.prefer {
					args = append(args, "--prefer-html")
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
				collectedAssets := tc.assets && tc.mime == "text/html"
				if collectedAssets {
					wantRequests = append(wantRequests, "/runtime?private-js=1", "/styles?private-css=1")
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
				for _, raw := range []string{"private-page", "private-start", "private-js", "private-css", "private-hop-cookie", "private-page-cookie", "private-asset-cookie", "sidebar_state", "data-slot", "--sidebar-width", "16rem", "3rem", "Express", "React ["} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("unexpected private/raw/implication data: %s", raw)
					}
				}
				wantRadix, wantTailwind := collectedAssets && !tc.failJS, collectedAssets
				if format != "json" {
					marker := "?"
					if format == "color" {
						marker = "\x1b[33m?\x1b[0m"
					}
					for _, expected := range []struct {
						name string
						want bool
					}{{"shadcn/ui", tc.want}, {"Radix UI", wantRadix}, {"Tailwind CSS", wantTailwind}} {
						count := 0
						if expected.want {
							count = 1
						}
						if strings.Contains(stdout.String(), marker+" "+expected.name+" [UI framework]") != expected.want || strings.Count(stdout.String(), " "+expected.name+" [UI framework]") != count {
							t.Errorf("findings=%s", &stdout)
						}
					}
					if !strings.Contains(stdout.String(), "nginx [web server]") {
						t.Error("page finding lost")
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				ids := []string{"nginx"}
				if wantRadix {
					ids = append(ids, "radix-ui")
				}
				if tc.want {
					ids = append(ids, "shadcn-ui")
				}
				if wantTailwind {
					ids = append(ids, "tailwindcss")
				}
				var gotIDs []string
				for _, f := range report.Findings {
					gotIDs = append(gotIDs, f.ID)
				}
				redirects := []output.Redirect{}
				if tc.hop != "" {
					redirects = append(redirects, output.Redirect{FromURL: server.URL + "/start?[redacted]", ToURL: server.URL + "/page?[redacted]", StatusCode: 302})
				}
				scope := "final_response"
				if tc.status >= 400 {
					scope = "http_error_response"
				}
				safePath := "/page?[redacted]"
				if tc.hop != "" {
					safePath = "/start?[redacted]"
				}
				if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || !report.QueryRedacted || report.URL != server.URL+safePath || report.FinalURL != server.URL+"/page?[redacted]" || report.HTTPStatus != tc.status || report.ResponseScope != scope || report.BodyBytes != len(body) || !reflect.DeepEqual(report.Redirects, redirects) || !reflect.DeepEqual(gotIDs, ids) || report.Findings[0].State != "detected" {
					t.Fatalf("report=%+v", report)
				}
				for _, f := range report.Findings {
					if f.ID == "nginx" {
						continue
					}
					if f.Category != "ui_framework" || f.State != "inferred" || len(f.Evidence) != 1 {
						t.Fatalf("finding=%+v", f)
					}
					var rule, url string
					var signals []output.Signal
					switch f.ID {
					case "shadcn-ui":
						rule = "sidebar-html"
						signals = []output.Signal{{Source: "html"}, {Source: "html"}, {Source: "html"}}
					case "radix-ui":
						rule = "asset-popover-style-mappings"
						url = server.URL + "/runtime?[redacted]"
						signals = []output.Signal{{Source: "asset_javascript"}}
					case "tailwindcss":
						rule = "asset-css-v3-banner-and-preflight"
						url = server.URL + "/styles?[redacted]"
						signals = []output.Signal{{Source: "asset_css"}, {Source: "asset_css"}}
					}
					e := f.Evidence[0]
					if e.RuleID != rule || e.AssetURL != url || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, signals) {
						t.Errorf("evidence=%+v", e)
					}
				}
				if !tc.assets {
					if report.Assets != nil {
						t.Error("default scan collected assets")
					}
					return
				}
				status, attempted, collected := "skipped", 0, 0
				if collectedAssets {
					status, attempted, collected = "complete", 2, 2
					if tc.failJS {
						status, collected = "incomplete", 1
					}
				}
				if report.Assets == nil || report.Assets.Status != status || report.Assets.Attempted != attempted || report.Assets.Collected != collected || len(report.Assets.Items) != attempted || report.Assets.Mode != "fingerprint_inspection" || report.Assets.Budget.Profile != "standard" {
					t.Fatalf("collection=%+v", report.Assets)
				}
				if tc.failJS && report.Assets.Items[0].Reason != "unsuccessful_status" {
					t.Errorf("item=%+v", report.Assets.Items[0])
				}
			})
		}
	}
}
