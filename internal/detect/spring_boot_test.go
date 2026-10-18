package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const springHeading = `<h1>Whitelabel Error Page</h1>`
const springServletFallback = `<p>This application has no explicit mapping for /error, so you are seeing this as a fallback.</p>`
const springReactiveFallback = `<p>This application has no configured error view, so you are seeing this as a fallback.</p>`
const springError = `<div>There was an unexpected error (type=Not Found, status=404).</div>`
const springReactiveError = `<div>[private-request-id] There was an unexpected error (type=Not Found, status=404).</div>`
const springMediaType = "application/vnd.spring-boot.actuator.v3+json"

func requireSpringBoot(t *testing.T, got []detect.Finding, state detect.State, rules ...string) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "spring-boot" || got[0].Name != "Spring Boot" || got[0].Category != detect.Framework || got[0].State != state || len(got[0].Evidence) != len(rules) {
		t.Fatalf("unexpected Spring Boot findings: %+v", got)
	}
	for i, id := range rules {
		e := got[0].Evidence[i]
		signals := []detect.Signal{{Source: detect.Header, Name: "Content-Type"}}
		if id == "whitelabel-error-html" {
			signals = []detect.Signal{{Source: detect.HTML}, {Source: detect.HTML}, {Source: detect.HTML}}
		}
		if e.RuleID != id || e.InferredFrom != "" || e.AssetURL != "" || !strings.Contains(e.Description, "may be an intermediary") || !reflect.DeepEqual(e.Signals, signals) {
			t.Errorf("unexpected %s evidence: %+v", id, e)
		}
		for _, raw := range []string{"private-spring-message", "private-request-id", "Synthetic timestamp", "Not Found", springMediaType} {
			if strings.Contains(e.Description, raw) {
				t.Errorf("raw response value leaked: %q", raw)
			}
		}
	}
}

func TestSpringBootActuatorMediaTypeBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for _, value := range []string{
		springMediaType, "application/vnd.spring-boot.actuator.v2+json",
		"\t APPLICATION/VND.SPRING-BOOT.ACTUATOR.V3+JSON \t",
		springMediaType + ";charset=UTF-8", springMediaType + ` ; CHARSET = "utf-8" `,
	} {
		t.Run("positive/"+value, func(t *testing.T) {
			got := engine.Detect(detect.Input{Headers: http.Header{"content-type": {value, value}, "CONTENT-TYPE": {"unrelated"}}})
			requireSpringBoot(t, got, detect.Detected, "actuator-media-type")
		})
	}
	for _, value := range []string{
		"", "application/json", "application/problem+json", "text/html", "Spring Boot",
		"application/vnd.spring-boot.actuator.v1+json", "application/vnd.spring-boot.actuator.v4+json",
		"application/vnd.spring-boot.actuator.v33+json", "application/vnd.spring-boot.actuator.v3+json-extra",
		"application/vnd.spring-boot.actuator.v3+xml", "application/vnd.other.actuator.v3+json",
		springMediaType + ", text/html", "text/html, " + springMediaType,
		springMediaType + ";charset=utf-16", springMediaType + ";profile=custom",
		springMediaType + ";charset=utf-8;charset=utf-8", springMediaType + ";",
		springMediaType + "\n", springMediaType + "\x00", "\u00a0" + springMediaType,
	} {
		t.Run("negative/"+value, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Headers: http.Header{"Content-Type": {value}}}); len(got) != 0 {
				t.Fatalf("unexpected findings: %+v", got)
			}
		})
	}
}

func TestSpringBootWhitelabelMarkerAndStatusCombinations(t *testing.T) {
	engine := bundledEngine(t)
	for _, variant := range []struct{ name, fallback, details string }{
		{"servlet", springServletFallback, springError},
		{"reactive", springReactiveFallback, springReactiveError},
	} {
		for mask := 0; mask < 8; mask++ {
			for _, status := range []int{0, 200, 302, 399, 400, 404, 500, 599, 600} {
				t.Run(fmt.Sprintf("%s/markers=%03b/status=%d", variant.name, mask, status), func(t *testing.T) {
					body := ""
					for i, marker := range []string{springHeading, variant.fallback, variant.details} {
						if mask&(1<<i) != 0 {
							body += marker
						}
					}
					input := detect.Input{HTTPStatus: status, HTML: []byte(body)}
					got := engine.Detect(input)
					if mask == 7 && status >= 400 && status <= 599 {
						requireSpringBoot(t, got, detect.Inferred, "whitelabel-error-html")
					} else if len(got) != 0 {
						t.Fatalf("partial markers or wrong status produced findings: %+v", got)
					}
					if fresh := engine.Detect(input); !reflect.DeepEqual(fresh, got) {
						t.Fatal("non-deterministic findings")
					}
					if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
						t.Fatalf("findings retained across scans: %+v", empty)
					}
				})
			}
		}
	}
	for _, name := range []string{"spring-boot-servlet-error.html", "spring-boot-reactive-error.html"} {
		body := htmlFixture(t, name)
		requireSpringBoot(t, engine.Detect(detect.Input{HTTPStatus: 404, HTML: body}), detect.Inferred, "whitelabel-error-html")
		requireSpringBoot(t, engine.Detect(detect.Input{HTTPStatus: 404, HTML: append(append([]byte(nil), body...), body...)}), detect.Inferred, "whitelabel-error-html")
		// A copied/commented example on an error response remains a raw-HTML limitation.
		requireSpringBoot(t, engine.Detect(detect.Input{HTTPStatus: 404, HTML: []byte("<!--" + string(body) + "-->")}), detect.Inferred, "whitelabel-error-html")
		for _, decoy := range []string{
			strings.Replace(string(body), "<h1>", "<h1-example>", 1),
			strings.Replace(string(body), "<p>", "<p-example>", 1),
			strings.Replace(string(body), "Whitelabel Error Page", "Whitelabel error page", 1),
			strings.Replace(string(body), "status=404", "status=200", 1),
			strings.Replace(string(body), "type=Not Found", "type=", 1),
			strings.Replace(string(body), "fallback.</p>", "fallback.</div>", 1),
			strings.ReplaceAll(string(body), "<", "&lt;"),
		} {
			if got := engine.Detect(detect.Input{HTTPStatus: 404, HTML: []byte(decoy)}); len(got) != 0 {
				t.Errorf("near-miss HTML produced findings: %+v", got)
			}
		}
	}
}

func TestSpringBootEvidenceIsolationAndPrecedence(t *testing.T) {
	engine := bundledEngine(t)
	body := []byte(springHeading + springServletFallback + springError)
	for _, input := range []detect.Input{
		{HTTPStatus: 404, Headers: http.Header{"X-Example": {string(body)}, "X-Powered-By": {springMediaType}, "Server": {springMediaType}, "Accept": {springMediaType}}},
		{HTTPStatus: 404, HTML: []byte(springMediaType), CookieNames: []string{"JSESSIONID", springMediaType}},
		{HTTPStatus: 404, Assets: []detect.Asset{{URL: "https://example.test/app.js", Source: detect.AssetJavaScript, Body: body}, {URL: "https://example.test/app.css", Source: detect.AssetCSS, Body: body}}},
		{HTTPStatus: 404, HTML: []byte(springHeading + springServletFallback), Assets: []detect.Asset{{URL: "https://example.test/app.js", Source: detect.AssetJavaScript, Body: []byte(springError)}}},
		{HTTPStatus: 404, Headers: http.Header{"X-Application-Context": {"application:8080"}}, HTML: []byte(`{"timestamp":"private","status":404,"error":"Not Found","path":"/error"}`)},
	} {
		if got := engine.Detect(input); len(got) != 0 {
			t.Fatalf("wrong-source or generic indicators produced findings: %+v", got)
		}
	}
	// The engine retains both rule matches if supplied both captures; the CLI
	// never treats an Actuator JSON response body as page HTML.
	input := detect.Input{HTTPStatus: 404, Headers: http.Header{"Content-Type": {springMediaType}}, HTML: body}
	got := engine.Detect(input)
	requireSpringBoot(t, got, detect.Detected, "actuator-media-type", "whitelabel-error-html")
	got[0].Evidence[0].Description, got[0].Evidence[0].Signals[0].Name = "caller mutation", "changed"
	requireSpringBoot(t, engine.Detect(input), detect.Detected, "actuator-media-type", "whitelabel-error-html")
	input.HTTPStatus = 200
	requireSpringBoot(t, engine.Detect(input), detect.Detected, "actuator-media-type")
}

func TestSpringBootIndependentBackendFindings(t *testing.T) {
	got := bundledEngine(t).Detect(detect.Input{
		HTTPStatus: 404, Headers: http.Header{"Server": {"Apache Tomcat/11.0.27"}},
		CookieNames: []string{"csrftoken"}, HTML: []byte(djangoInput + springHeading + springServletFallback + springError),
	})
	ids := []string{}
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	if !reflect.DeepEqual(ids, []string{"django", "python", "spring-boot", "tomcat"}) {
		t.Fatalf("unexpected mixed backend findings: %+v", got)
	}
	requireDjangoFinding(t, got[:1])
	requireLanguageInference(t, got[1:2], "python", "django")
	requireSpringBoot(t, got[2:3], detect.Inferred, "whitelabel-error-html")
	requireTomcat(t, got[3:], detect.Detected, "server-header")
}
