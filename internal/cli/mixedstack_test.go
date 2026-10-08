package cli_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"webscan/internal/cli"
	"webscan/internal/detect"
	"webscan/internal/output"
)

type mixedEvidence struct {
	rule, from string
	signals    []output.Signal
}

type mixedFinding struct {
	id, name, category, label, state string
	evidence                         []mixedEvidence
}

func mixedHeader(rule, name string) mixedEvidence {
	return mixedEvidence{rule: rule, signals: []output.Signal{{Source: "header", Name: name}}}
}

// Expectations are independent of the engine's own detection results.
func expectedMixedStack(direct, html bool, action, serverID, serverName string) []mixedFinding {
	cookies := []output.Signal{{Source: "cookie"}, {Source: "cookie"}}
	want := []mixedFinding{{"aws-alb", "AWS Application Load Balancer", "load_balancer", "load balancer", "inferred", []mixedEvidence{{rule: "stickiness-cookie-pair", signals: cookies}}}}
	if action != "" {
		want = append(want, mixedFinding{"aws-waf", "AWS WAF", "waf", "WAF", "detected", []mixedEvidence{mixedHeader("action-header", "X-Amzn-Waf-Action")}})
	}
	want = append(want,
		mixedFinding{"cloudflare", "Cloudflare", "cdn", "CDN/edge", "detected", []mixedEvidence{mixedHeader("ray-header", "Cf-Ray")}},
		mixedFinding{"cloudfront", "Amazon CloudFront", "cdn", "CDN/edge", "detected", []mixedEvidence{mixedHeader("via-header", "Via")}},
		mixedFinding{"laravel", "Laravel", "framework", "framework", "inferred", []mixedEvidence{{rule: "default-cookie-pair", signals: cookies}}},
	)
	if html {
		want = append(want, mixedFinding{"django", "Django", "framework", "framework", "inferred", []mixedEvidence{{rule: "csrf-cookie-and-input", signals: []output.Signal{{Source: "cookie"}, {Source: "html"}}}}})
	}
	if html || direct {
		next := mixedFinding{"nextjs", "Next.js", "framework", "framework", "inferred", nil}
		if html {
			next.evidence = append(next.evidence, mixedEvidence{rule: "pages-html-markers", signals: []output.Signal{{Source: "html"}, {Source: "html"}}})
		}
		if direct {
			next.state = "detected"
			next.evidence = append(next.evidence, mixedHeader("powered-by-header", "X-Powered-By"))
		}
		want = append(want, next)
	}
	if html || direct {
		nuxt := mixedFinding{"nuxt", "Nuxt", "framework", "framework", "inferred", nil}
		if html {
			nuxt.evidence = append(nuxt.evidence, mixedEvidence{rule: "payload-html-markers", signals: []output.Signal{{Source: "html"}, {Source: "html"}}})
		}
		if direct {
			nuxt.state = "detected"
			nuxt.evidence = append(nuxt.evidence, mixedHeader("powered-by-header", "X-Powered-By"))
		}
		want = append(want, nuxt)
	}
	want = append(want, mixedFinding{serverID, serverName, "web_server", "web server", "detected", []mixedEvidence{mixedHeader("server-header", "Server")}})
	php := mixedFinding{"php", "PHP", "language", "language", "inferred", nil}
	if direct {
		php.state = "detected"
		php.evidence = append(php.evidence, mixedHeader("powered-by-header", "X-Powered-By"))
	}
	php.evidence = append(php.evidence, mixedEvidence{from: "laravel", signals: []output.Signal{}})
	want = append(want, php)
	if html {
		want = append(want, mixedFinding{"rails", "Ruby on Rails", "framework", "framework", "inferred", []mixedEvidence{{rule: "csrf-meta-pair", signals: []output.Signal{{Source: "html"}, {Source: "html"}}}}})
		want = append(want, mixedFinding{"wordpress", "WordPress", "cms", "CMS", "inferred", []mixedEvidence{{rule: "generator-meta", signals: []output.Signal{{Source: "html"}}}}})
	}
	sort.Slice(want, func(i, j int) bool { return want[i].id < want[j].id })
	return want
}

func TestMixedStackThroughCLI(t *testing.T) {
	body, err := os.ReadFile("testdata/mixed-stack.html")
	if err != nil {
		t.Fatal(err)
	}
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	for _, exposed := range []struct{ id, name, banner, invalid string }{
		{"apache", "Apache HTTP Server", "Apache/2.4.62 (Unix) PHP/8.3.12", "Apache/2..4"},
		{"iis", "Microsoft IIS", "Microsoft-IIS/10.0", "Microsoft-IIS/10..0"},
		{"nginx", "nginx", "nginx/1.26.2 (Ubuntu)", "nginx/1..2"},
	} {
		for _, tc := range []struct {
			name, mode, contentType, action string
			status                          int
			direct, limited                 bool
		}{
			{"indirect-application", "full", "text/html", "", 200, false, false},
			{"direct-upgrades", "full", "text/html", "", 200, true, false},
			{"challenge-response", "full", "text/html", "challenge", 202, true, false},
			{"captcha-response", "full", "text/html", "captcha", 405, true, false},
			{"non-html-error", "full", "text/plain", "", 403, false, false},
			{"non-html-direct", "full", "text/plain", "", 200, true, false},
			{"near-misses", "decoys", "text/html", "", 403, false, false},
			{"redirect-evidence-only", "empty", "text/html", "", 200, false, false},
			{"body-limit-no-partial-findings", "full", "text/html", "challenge", 202, true, true},
		} {
			for _, format := range []string{"terminal", "json"} {
				t.Run(exposed.id+"/"+tc.name+"/"+format, func(t *testing.T) {
					finalBody := string(body)
					if tc.mode == "decoys" {
						finalBody = `<meta name="generator" content="WordPress-compatible"><script data-id="__NEXT_DATA__"></script><script data-src="/_next/static/main.js"></script>challenge captcha AWS WAF`
						finalBody += `<script id="__NUXT_DATA__"></script><script data-src="/_nuxt/fixture.js"></script><input type="hidden" data-name="csrfmiddlewaretoken"><meta name="csrf-param" content="authenticity_token"><meta name="csrf-token" content="">`
					} else if tc.mode == "empty" {
						finalBody = "<html>No identifying signals</html>"
					}
					var mu sync.Mutex
					var paths []string
					replayed := false
					server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
						mu.Lock()
						paths = append(paths, r.Method+" "+r.URL.Path)
						replayed = replayed || r.Header.Get("Cookie") != ""
						mu.Unlock()
						setCookies := func(names ...string) {
							for _, name := range names {
								http.SetCookie(w, &http.Cookie{Name: name, Value: "private-cookie-value", Path: "/"})
							}
						}
						switch r.URL.Path {
						case "/start":
							w.Header().Set("X-Powered-By", "Express")
							w.Header().Set("X-Amzn-Waf-Action", "captcha")
							w.Header().Set("CF-Ray", "abcdef0123456789-LIS")
							setCookies("AWSELB", "AWSELBCORS", "AWSALB", "laravel_session", "csrftoken")
							w.Header().Add("X-Powered-By", "Nuxt")
							w.Header().Set("Content-Type", "text/html")
							w.Header().Set("Location", "/middle")
							w.WriteHeader(http.StatusFound)
							fmt.Fprint(w, string(body))
						case "/middle":
							w.Header().Set("Server", "Microsoft-IIS/10.0")
							w.Header().Set("X-Generator", "Drupal 11")
							setCookies("AWSALBCORS", "XSRF-TOKEN")
							http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
						case "/final":
							w.Header().Set("Content-Type", tc.contentType)
							w.Header().Set("X-Request-ID", "private-request-id")
							if tc.mode == "full" {
								w.Header().Set("Server", exposed.banner)
								w.Header().Add("CF-Ray", "230b030023ae2822-SJC")
								w.Header().Add("CF-Ray", "230b030023ae2822-SJC")
								w.Header().Set("Via", "1.1 fixture123.cloudfront.net (CloudFront)")
								setCookies("AWSALB", "AWSALBCORS", "laravel_session", "XSRF-TOKEN", "AWSALB", "csrftoken", "csrftoken")
								if tc.direct {
									for _, value := range []string{"PHP/8.3.12", "Next.js", "Nuxt", "PHP/8.3.12", "Nuxt"} {
										w.Header().Add("X-Powered-By", value)
									}
								}
								if tc.action != "" {
									w.Header().Set("X-Amzn-Waf-Action", tc.action)
								}
							} else if tc.mode == "decoys" {
								w.Header().Set("CF-Ray", "230b030023ae2822-SJC-extra")
								w.Header().Set("Via", "1.1 fixture.cloudfront.net.example.test (CloudFront)")
								w.Header().Set("X-Amzn-Waf-Action", "challenge-extra")
								w.Header().Set("Server", exposed.invalid)
								w.Header().Set("X-Powered-By", "PHPish")
								w.Header().Add("X-Powered-By", "Nuxt-compatible")
								setCookies("AWSALBCORS", "XSRF-TOKEN", "AWSELBCORS", "csrftoken", "sessionid", "_app_session")
							}
							w.WriteHeader(tc.status)
							fmt.Fprint(w, finalBody)
						default:
							http.NotFound(w, r)
						}
					}))
					defer server.Close()
					args := []string{"--no-color"}
					if format == "json" {
						args = append(args, "--json")
					}
					if tc.limited {
						args = append(args, "--max-body=32")
					}
					var stdout, stderr bytes.Buffer
					code := cli.Run(append(args, server.URL+"/start#fragment"), &stdout, &stderr, "dev")
					mu.Lock()
					visited, hadCookies := append([]string(nil), paths...), replayed
					mu.Unlock()
					if !reflect.DeepEqual(visited, []string{"GET /start", "GET /middle", "GET /final"}) || hadCookies {
						t.Errorf("unexpected requests/cookie replay: paths=%v cookies=%v", visited, hadCookies)
					}
					if tc.limited {
						if code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
							t.Fatalf("body limit must fail without partial findings: exit=%d stdout=%q stderr=%q", code, &stdout, &stderr)
						}
						return
					}
					if code != 0 || stderr.Len() != 0 {
						t.Fatalf("exit=%d stderr=%q", code, &stderr)
					}
					for _, absent := range []string{"private-cookie-value", "private-request-id", "private-rails-token", "private-django-token", exposed.banner, exposed.invalid, "230b030023ae2822-SJC", "abcdef0123456789-LIS", "fixture123.cloudfront.net", "#fragment", "\x1b"} {
						if strings.Contains(stdout.String(), absent) {
							t.Errorf("unexpected raw data in output: %q", absent)
						}
					}
					want := []mixedFinding{}
					if tc.mode == "full" {
						want = expectedMixedStack(tc.direct, tc.contentType == "text/html", tc.action, exposed.id, exposed.name)
					}
					if format == "terminal" {
						gotLines, wantLines := []string{}, []string{}
						for _, line := range strings.Split(stdout.String(), "\n") {
							if (strings.HasPrefix(line, "✓ ") || strings.HasPrefix(line, "? ")) && strings.Contains(line, " [") {
								gotLines = append(gotLines, line)
							}
						}
						for _, finding := range want {
							marker := "?"
							if finding.state == "detected" {
								marker = "✓"
							}
							wantLines = append(wantLines, marker+" "+finding.name+" ["+finding.label+"]")
						}
						if !reflect.DeepEqual(gotLines, wantLines) {
							t.Errorf("findings=%v want=%v", gotLines, wantLines)
						}
						if len(want) == 0 && !strings.Contains(stdout.String(), "No technologies detected.") {
							t.Error("missing empty-result message")
						}
						if strings.Contains(stdout.String(), "Findings describe the returned HTTP error page.") != (tc.status >= 400) {
							t.Error("incorrect error-response scope")
						}
						return
					}
					var report output.Report
					if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
						t.Fatal(err)
					}
					scope := "final_response"
					if tc.status >= 400 {
						scope = "http_error_response"
					}
					wantRedirects := []output.Redirect{
						{FromURL: server.URL + "/start", ToURL: server.URL + "/middle", StatusCode: 302},
						{FromURL: server.URL + "/middle", ToURL: server.URL + "/final", StatusCode: 307},
					}
					if report.SchemaVersion != 1 || report.CatalogSize != engine.Len() || report.URL != server.URL+"/start" || report.FinalURL != server.URL+"/final" || report.HTTPStatus != tc.status || report.ResponseScope != scope || report.BodyBytes != len(finalBody) || !reflect.DeepEqual(report.Redirects, wantRedirects) {
						t.Errorf("unexpected metadata: %+v", report)
					}
					if report.Findings == nil || len(report.Findings) != len(want) {
						t.Fatalf("findings=%+v want=%+v", report.Findings, want)
					}
					for i, expected := range want {
						got := report.Findings[i]
						if got.ID != expected.id || got.Name != expected.name || got.Category != expected.category || got.State != expected.state || len(got.Evidence) != len(expected.evidence) {
							t.Fatalf("finding=%+v want=%+v", got, expected)
						}
						for j, evidence := range got.Evidence {
							wantEvidence := expected.evidence[j]
							if evidence.Description == "" || evidence.RuleID != wantEvidence.rule || evidence.InferredFrom != wantEvidence.from || !reflect.DeepEqual(evidence.Signals, wantEvidence.signals) {
								t.Errorf("%s evidence=%+v want=%+v", got.ID, evidence, wantEvidence)
							}
						}
					}
				})
			}
		}
	}
}
