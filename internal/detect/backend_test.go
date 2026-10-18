package detect_test

import (
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func TestCombinedBackendEvidence(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct {
		name, server, omit, ids  string
		springRules, tomcatRules string
		status                   int
		directPHP, assetsOnly    bool
	}{
		{
			name: "jetty-and-both-error-identities", server: "Jetty(12.0.16)", status: 404, directPHP: true,
			ids: "django jetty laravel php python rails ruby spring-boot tomcat", springRules: "whitelabel-error-html", tomcatRules: "error-report-html",
		},
		{
			name: "tomcat-direct-upgrade", server: "Apache Tomcat/11.0.27", status: 404, directPHP: true,
			ids: "django laravel php python rails ruby spring-boot tomcat", springRules: "whitelabel-error-html", tomcatRules: "error-report-html server-header",
		},
		{
			name: "successful-page-keeps-direct-tomcat", server: "Apache Tomcat/11.0.27", status: 200, directPHP: true,
			ids: "django laravel php python rails ruby tomcat", tomcatRules: "server-header",
		},
		{
			name: "successful-page-keeps-languages", server: "Jetty(12.0.16)", status: 200, directPHP: true,
			ids: "django jetty laravel php python rails ruby",
		},
		{
			name: "unknown-status-does-not-gate-older-rules", server: "Jetty(12.0.16)", directPHP: true,
			ids: "django jetty laravel php python rails ruby",
		},
		{
			name: "malformed-server-does-not-block-independent-html", server: "Jetty(12..16)", status: 500, directPHP: true,
			ids: "django laravel php python rails ruby spring-boot tomcat", springRules: "whitelabel-error-html", tomcatRules: "error-report-html",
		},
		{
			name: "partial-spring-markers", server: "Jetty(12.0.16)", status: 404, directPHP: true, omit: "spring-heading",
			ids: "django jetty laravel php python rails ruby tomcat", tomcatRules: "error-report-html",
		},
		{
			name: "partial-tomcat-markers", server: "Jetty(12.0.16)", status: 404, directPHP: true, omit: "tomcat-footer",
			ids: "django jetty laravel php python rails ruby spring-boot", springRules: "whitelabel-error-html",
		},
		{
			name: "missing-django-cookie", server: "Jetty(12.0.16)", status: 404, directPHP: true, omit: "django-cookie",
			ids: "jetty laravel php rails ruby spring-boot tomcat", springRules: "whitelabel-error-html", tomcatRules: "error-report-html",
		},
		{
			name: "missing-rails-token", server: "Jetty(12.0.16)", status: 404, directPHP: true, omit: "rails-token",
			ids: "django jetty laravel php python spring-boot tomcat", springRules: "whitelabel-error-html", tomcatRules: "error-report-html",
		},
		{
			name: "direct-php-without-laravel", server: "Jetty(12.0.16)", status: 404, directPHP: true, omit: "laravel-session",
			ids: "django jetty php python rails ruby spring-boot tomcat", springRules: "whitelabel-error-html", tomcatRules: "error-report-html",
		},
		{
			name: "php-remains-inferred-without-direct-header", server: "Jetty(12.0.16)", status: 404,
			ids: "django jetty laravel php python rails ruby spring-boot tomcat", springRules: "whitelabel-error-html", tomcatRules: "error-report-html",
		},
		{
			name: "missing-laravel-does-not-borrow-other-languages", server: "Jetty(12.0.16)", status: 404, omit: "laravel-session",
			ids: "django jetty python rails ruby spring-boot tomcat", springRules: "whitelabel-error-html", tomcatRules: "error-report-html",
		},
		{
			name: "partial-pairs-do-not-complete-each-other", server: "Apache Tomcat/11.0.27", status: 404, directPHP: true,
			omit: "django-input rails-token laravel-csrf spring-heading tomcat-footer", ids: "php tomcat", tomcatRules: "server-header",
		},
		{
			name: "complete-html-in-assets-only", server: "Jetty(12.0.16)", status: 404, assetsOnly: true,
			ids: "jetty laravel php",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := detect.Input{HTTPStatus: tc.status, Headers: http.Header{"Server": {tc.server, tc.server}}}
			if tc.directPHP {
				input.Headers["X-Powered-By"] = []string{"PHP/8.3.12", "PHP/8.3.12"}
			}
			omitted := strings.Fields(tc.omit)
			for _, marker := range []struct{ id, cookie, html string }{
				{"django-cookie", "csrftoken", ""}, {"django-input", "", djangoInput},
				{"rails-param", "", railsParam}, {"rails-token", "", railsToken},
				{"laravel-session", "laravel_session", ""}, {"laravel-csrf", "XSRF-TOKEN", ""},
				{"spring-heading", "", springHeading}, {"spring-fallback", "", springReactiveFallback}, {"spring-details", "", springReactiveError},
				{"tomcat-title", "", tomcatTitle}, {"tomcat-heading", "", tomcatHeading}, {"tomcat-footer", "", tomcatFooter},
			} {
				if slices.Contains(omitted, marker.id) {
					continue
				}
				if marker.cookie != "" {
					input.CookieNames = append(input.CookieNames, marker.cookie, marker.cookie)
				}
				input.HTML = append(input.HTML, marker.html...)
			}
			// A missing page marker is available in both asset kinds. Neither
			// asset body may complete a page rule or an associated language.
			fullHTML := []byte(djangoInput + railsParam + railsToken + springHeading + springReactiveFallback + springReactiveError + tomcatTitle + tomcatHeading + tomcatFooter)
			input.Assets = []detect.Asset{
				{URL: "https://example.test/app.js", Source: detect.AssetJavaScript, Body: fullHTML},
				{URL: "https://example.test/app.css", Source: detect.AssetCSS, Body: fullHTML},
			}
			if tc.assetsOnly {
				input.HTML = nil
			}
			got := engine.Detect(input)
			ids := make([]string, 0, len(got))
			for _, finding := range got {
				ids = append(ids, finding.ID)
			}
			wantIDs := strings.Fields(tc.ids)
			if !reflect.DeepEqual(ids, wantIDs) {
				t.Fatalf("IDs=%v want=%v; findings=%+v", ids, wantIDs, got)
			}
			for i, finding := range got {
				one := got[i : i+1]
				switch finding.ID {
				case "django":
					requireDjangoFinding(t, one)
				case "rails":
					requireRailsFinding(t, one)
				case "python", "ruby":
					parent := map[string]string{"python": "django", "ruby": "rails"}[finding.ID]
					requireLanguageInference(t, one, finding.ID, parent)
				case "php":
					if !tc.directPHP {
						requireLanguageInference(t, one, "php", "laravel")
						break
					}
					want := []detect.Evidence{{RuleID: "powered-by-header", Description: "X-Powered-By header reports PHP", Signals: []detect.Signal{{Source: detect.Header, Name: "X-Powered-By"}}}}
					if slices.Contains(wantIDs, "laravel") {
						want = append(want, detect.Evidence{Description: "Inferred from Laravel", InferredFrom: "laravel"})
					}
					if finding.Name != "PHP" || finding.Category != detect.Language || finding.State != detect.Detected || !reflect.DeepEqual(finding.Evidence, want) {
						t.Errorf("direct PHP lost state or relationship provenance: %+v", finding)
					}
				case "laravel", "jetty":
					name, category, state, rule := "Laravel", detect.Framework, detect.Inferred, "default-cookie-pair"
					signals := []detect.Signal{{Source: detect.Cookie}, {Source: detect.Cookie}}
					if finding.ID == "jetty" {
						name, category, state, rule = "Jetty", detect.WebServer, detect.Detected, "server-header"
						signals = []detect.Signal{{Source: detect.Header, Name: "Server"}}
					}
					if finding.Name != name || finding.Category != category || finding.State != state || len(finding.Evidence) != 1 {
						t.Fatalf("unexpected finding: %+v", finding)
					}
					e := finding.Evidence[0]
					if e.RuleID != rule || e.Description == "" || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, signals) {
						t.Errorf("unexpected evidence: %+v", e)
					}
				case "spring-boot":
					requireSpringBoot(t, one, detect.Inferred, strings.Fields(tc.springRules)...)
				case "tomcat":
					state := detect.Inferred
					if strings.Contains(tc.tomcatRules, "server-header") {
						state = detect.Detected
					}
					requireTomcat(t, one, state, strings.Fields(tc.tomcatRules)...)
				}
				for _, evidence := range finding.Evidence {
					if evidence.AssetURL != "" || strings.Contains(evidence.Description, "private-") {
						t.Errorf("page/relationship evidence leaked an asset or raw value: %+v", evidence)
					}
				}
			}
			if fresh := engine.Detect(input); !reflect.DeepEqual(fresh, got) {
				t.Error("repeated scan changed backend findings")
			}
			if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
				t.Errorf("backend findings leaked into an empty scan: %+v", empty)
			}
		})
	}
}
