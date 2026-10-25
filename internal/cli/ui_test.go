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

func TestCLICombinedUIFrameworks(t *testing.T) {
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	read := func(name string) string {
		t.Helper()
		body, err := os.ReadFile("../detect/testdata/coverage/" + name)
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	b, tw3, tw4 := read("bootstrap-5.3.min.css"), read("tailwind-3.4.css"), read("tailwind-4.1.min.css")
	r, s := read("radix-popover.js")+read("radix-tooltip.min.js"), read("shadcn-sidebar.html")
	for _, tc := range []struct {
		name, failure, reason                                                  string
		disabled, separate, reverse, partial, prefer, truncated, badMIME, late bool
	}{
		{name: "shared-css"},
		{name: "separate-css-reversed", separate: true, reverse: true, prefer: true},
		{name: "default-off", disabled: true},
		{name: "partial-page-with-complete-asset-decoys", partial: true},
		{name: "shared-css-failure", failure: "/styles", reason: "unsuccessful_status"},
		{name: "bootstrap-failure-keeps-tailwind", separate: true, failure: "/styles", reason: "unsuccessful_status"},
		{name: "tailwind-failure-keeps-bootstrap", separate: true, failure: "/tailwind", reason: "unsuccessful_status"},
		{name: "javascript-failure-keeps-css-and-page", failure: "/runtime", reason: "unsuccessful_status"},
		{name: "css-wrong-mime", failure: "/styles", reason: "unsuitable_content_type", badMIME: true},
		{name: "incomplete-css-prefix", failure: "/styles", reason: "request_or_body_error", truncated: true},
		{name: "later-failure-preserves-all", failure: "/late", reason: "unsuccessful_status", late: true},
	} {
		for _, format := range []string{"json", "plain", "color"} {
			t.Run(tc.name+"/"+format, func(t *testing.T) {
				paths := []string{"/runtime?private-js=1", "/styles?private-css=1"}
				if tc.separate {
					paths = append(paths, "/tailwind?private-tw=1")
				}
				if tc.reverse {
					for i, j := 0, len(paths)-1; i < j; i, j = i+1, j-1 {
						paths[i], paths[j] = paths[j], paths[i]
					}
				}
				if tc.late {
					paths = append(paths, "/late?private-late=1")
				}
				page := s
				if tc.partial {
					page = `<div data-slot="sidebar-inner" data-sidebar="sidebar"><ul data-slot="sidebar-menu" data-sidebar="menu">`
				}
				// Inline JS/CSS may not supply asset evidence. Complete shadcn HTML
				// appears only in the asset decoys when the final page is partial.
				page += "<style>" + b + tw3 + tw4 + "</style><script>" + r + "</script>"
				for _, path := range paths {
					if strings.HasPrefix(path, "/styles") || strings.HasPrefix(path, "/tailwind") {
						page += `<link rel="stylesheet" href="` + path + `">`
					} else {
						page += `<script src="` + path + `"></script>`
					}
				}
				page += `<link rel="stylesheet" href="/styles?private-css=1#duplicate">`
				var mu sync.Mutex
				var requests []string
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
					mu.Lock()
					requests = append(requests, req.RequestURI)
					mu.Unlock()
					wantAccept := ""
					if tc.prefer && (req.URL.Path == "/start" || req.URL.Path == "/page") {
						wantAccept = "text/html, application/xhtml+xml;q=0.9, */*;q=0.8"
					}
					if req.Method != http.MethodGet || req.Header.Get("User-Agent") != "webscan" || req.Header.Get("Cookie") != "" || req.Header.Get("Authorization") != "" || req.Header.Get("Accept") != wantAccept || (req.URL.Path != "/page" && req.Header.Get("Referer") != "") {
						t.Errorf("request=%s %+v", req.Method, req.Header)
					}
					switch req.URL.Path {
					case "/start":
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Server", "Apache")
						w.Header().Set("X-Powered-By", "Express")
						w.Header().Set("Set-Cookie", "hop=private-hop-cookie; Path=/")
						w.Header().Set("Location", "/page?private-page=1")
						w.WriteHeader(http.StatusFound)
						fmt.Fprint(w, s)
					case "/page":
						w.Header().Set("Content-Type", "text/html")
						w.Header().Set("Server", "nginx")
						w.Header().Set("Set-Cookie", "page=private-page-cookie; Path=/")
						w.WriteHeader(http.StatusForbidden)
						fmt.Fprint(w, page)
					case "/runtime", "/styles", "/tailwind", "/late":
						w.Header().Set("X-Powered-By", "Express")
						w.Header().Set("Set-Cookie", "asset=private-asset-cookie; Path=/")
						mime, content := "text/css", b
						switch req.URL.Path {
						case "/runtime":
							mime, content = "text/javascript", r+"/* "+b+tw3+tw4+s+" */"
						case "/styles":
							if !tc.separate {
								content += tw3
							}
							content += "/* " + r + s + " */"
						case "/tailwind":
							content = tw4 + "/* " + r + s + " */"
						case "/late":
							mime, content = "text/javascript", "private-late-body"
						}
						if req.URL.Path == tc.failure && tc.badMIME {
							mime = "text/javascript"
						}
						w.Header().Set("Content-Type", mime)
						if req.URL.Path == tc.failure {
							if tc.truncated {
								w.Header().Set("Content-Length", fmt.Sprint(len(content)+100))
							} else if !tc.badMIME {
								w.WriteHeader(http.StatusForbidden)
							}
						}
						fmt.Fprint(w, content)
					default:
						t.Errorf("unexpected request: %s", req.RequestURI)
						w.WriteHeader(http.StatusNotFound)
					}
				}))
				defer server.Close()
				args := []string{"--redact-query"}
				if !tc.disabled {
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
				var stdout, stderr bytes.Buffer
				if code := cli.Run(append(args, server.URL+"/start?private-start=1"), &stdout, &stderr, "dev"); code != 0 || stderr.Len() != 0 {
					t.Fatalf("code=%d stderr=%s", code, &stderr)
				}
				wantRequests := []string{"/start?private-start=1", "/page?private-page=1"}
				if !tc.disabled {
					wantRequests = append(wantRequests, paths...)
				}
				mu.Lock()
				gotRequests := append([]string(nil), requests...)
				mu.Unlock()
				if !reflect.DeepEqual(gotRequests, wantRequests) {
					t.Errorf("requests=%v want=%v", gotRequests, wantRequests)
				}
				for _, raw := range []string{"private-", "--bs-btn-", "--tw-", "--radix-", "--sidebar-width", "data-slot", "Express", "Apache", "React ["} {
					if strings.Contains(stdout.String(), raw) {
						t.Errorf("raw/private/other-response data leaked: %s", raw)
					}
				}
				wantB := !tc.disabled && tc.failure != "/styles"
				wantTW := !tc.disabled && ((tc.separate && tc.failure != "/tailwind") || (!tc.separate && tc.failure != "/styles"))
				wantR, wantS := !tc.disabled && tc.failure != "/runtime", !tc.partial
				if format != "json" {
					marker := "?"
					if format == "color" {
						marker = "\x1b[33m?\x1b[0m"
					}
					for _, expected := range []struct {
						name string
						want bool
					}{{"Bootstrap", wantB}, {"Radix UI", wantR}, {"shadcn/ui", wantS}, {"Tailwind CSS", wantTW}} {
						count := 0
						if expected.want {
							count = 1
						}
						if strings.Contains(stdout.String(), marker+" "+expected.name+" [UI framework]") != expected.want || strings.Count(stdout.String(), " "+expected.name+" [UI framework]") != count {
							t.Errorf("findings=%s", &stdout)
						}
					}
					if !strings.Contains(stdout.String(), "nginx [web server]") {
						t.Error("page server finding lost")
					}
					return
				}
				var report output.Report
				if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
					t.Fatal(err)
				}
				ids := []string{}
				if wantB {
					ids = append(ids, "bootstrap")
				}
				ids = append(ids, "nginx")
				if wantR {
					ids = append(ids, "radix-ui")
				}
				if wantS {
					ids = append(ids, "shadcn-ui")
				}
				if wantTW {
					ids = append(ids, "tailwindcss")
				}
				var gotIDs []string
				for _, f := range report.Findings {
					gotIDs = append(gotIDs, f.ID)
				}
				if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || !report.QueryRedacted || report.URL != server.URL+"/start?[redacted]" || report.FinalURL != server.URL+"/page?[redacted]" || report.HTTPStatus != 403 || report.ResponseScope != "http_error_response" || report.BodyBytes != len(page) || !reflect.DeepEqual(report.Redirects, []output.Redirect{{FromURL: server.URL + "/start?[redacted]", ToURL: server.URL + "/page?[redacted]", StatusCode: 302}}) || !reflect.DeepEqual(gotIDs, ids) {
					t.Fatalf("report=%+v", report)
				}
				type expectedEvidence struct {
					rule, path, source string
					count              int
				}
				tRule, tPath, tCount := "asset-css-v3-banner-and-preflight", "/styles", 2
				if tc.separate {
					tRule, tPath, tCount = "asset-css-v4-banner-and-translate", "/tailwind", 3
				}
				for _, f := range report.Findings {
					if f.ID == "nginx" {
						if f.State != "detected" {
							t.Errorf("server state=%s", f.State)
						}
						continue
					}
					var evidence []expectedEvidence
					switch f.ID {
					case "bootstrap":
						evidence = []expectedEvidence{{"asset-css-banner-and-buttons", "/styles", "asset_css", 2}}
					case "radix-ui":
						evidence = []expectedEvidence{{"asset-popover-style-mappings", "/runtime", "asset_javascript", 1}, {"asset-tooltip-style-mappings", "/runtime", "asset_javascript", 1}}
					case "shadcn-ui":
						evidence = []expectedEvidence{{"sidebar-html", "", "html", 3}}
					case "tailwindcss":
						evidence = []expectedEvidence{{tRule, tPath, "asset_css", tCount}}
					}
					if f.Category != "ui_framework" || f.State != "inferred" || len(f.Evidence) != len(evidence) {
						t.Fatalf("finding=%+v", f)
					}
					for i, e := range f.Evidence {
						w := evidence[i]
						url := ""
						if w.path != "" {
							url = server.URL + w.path + "?[redacted]"
						}
						signals := make([]output.Signal, w.count)
						for j := range signals {
							signals[j].Source = w.source
						}
						if e.RuleID != w.rule || e.AssetURL != url || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, signals) {
							t.Errorf("evidence=%+v want=%+v", e, w)
						}
					}
				}
				if tc.disabled {
					if report.Assets != nil {
						t.Error("default scan collected assets")
					}
					return
				}
				status, collected := "complete", len(paths)
				if tc.failure != "" {
					status, collected = "incomplete", collected-1
				}
				if report.Assets == nil || report.Assets.Status != status || report.Assets.Attempted != len(paths) || report.Assets.Collected != collected || len(report.Assets.Items) != len(paths) || report.Assets.Mode != "fingerprint_inspection" || report.Assets.Budget.Profile != "standard" || report.Assets.Duplicates != 1 {
					t.Fatalf("collection=%+v", report.Assets)
				}
				for i, path := range paths {
					base, _, _ := strings.Cut(path, "?")
					item := report.Assets.Items[i]
					itemStatus, reason := "collected", ""
					if base == tc.failure {
						itemStatus, reason = "failed", tc.reason
					}
					if item.URL != server.URL+base+"?[redacted]" || item.Status != itemStatus || item.Reason != reason {
						t.Errorf("item=%+v", item)
					}
				}
			})
		}
	}
}
