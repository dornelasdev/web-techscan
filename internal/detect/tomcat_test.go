package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const tomcatTitle = `<title>HTTP Status 404 – Not Found</title>`
const tomcatHeading = `<h1>HTTP Status 404 – Not Found</h1>`
const tomcatFooter = `<h3>Apache Tomcat/11.0.27</h3>`
const tomcatPoweredBy = "Servlet/6.1 JSP/4.0 (Apache Tomcat/11.0.27 Java/Private Vendor/21.0.8+9-LTS)"

func requireTomcat(t *testing.T, got []detect.Finding, state detect.State, rules ...string) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "tomcat" || got[0].Name != "Apache Tomcat" || got[0].Category != detect.WebServer || got[0].State != state || len(got[0].Evidence) != len(rules) {
		t.Fatalf("unexpected Tomcat findings: %+v", got)
	}
	for i, id := range rules {
		e := got[0].Evidence[i]
		signals := []detect.Signal{{Source: detect.Header, Name: "Server"}}
		if id == "powered-by-header" {
			signals[0].Name = "X-Powered-By"
		} else if id == "error-report-html" {
			signals = []detect.Signal{{Source: detect.HTML}, {Source: detect.HTML}, {Source: detect.HTML}}
		}
		if e.RuleID != id || e.InferredFrom != "" || e.AssetURL != "" || !strings.Contains(e.Description, "may be an intermediary") || !reflect.DeepEqual(e.Signals, signals) {
			t.Errorf("unexpected %s evidence: %+v", id, e)
		}
		for _, raw := range []string{"11.0.27", "Private Vendor", "21.0.8", "private-error-message"} {
			if strings.Contains(e.Description, raw) {
				t.Errorf("raw response value leaked into evidence: %s", raw)
			}
		}
	}
}

func TestTomcatHeaderBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct {
		name, rule         string
		positive, negative []string
	}{
		{"Server", "server-header", []string{"Apache Tomcat", "Apache Tomcat/11.0.27", "Apache Tomcat/9.0.100", "\t aPaChE\tToMcAt/10.1.40 \t"}, []string{
			"Tomcat", "Tomcat/11.0.27", "Apache-Tomcat/11.0.27", "Apache-Coyote/1.1", "Apache Tomcat/",
			"Apache Tomcat/11.0", "Apache Tomcat/11..27", "Apache Tomcat/11.0.27.1", "Apache Tomcat/11.0.27-M1",
			"Apache Tomcat/11.0.27 proxy", "Apache Tomcat/11.0.27, nginx", "proxy Apache Tomcat/11.0.27",
			"Apache Tomcat/11.0.27 (Unix)", "Apache Tomcat/11.0.27\n", "Apache Tomcat/11.0.27\x00",
		}},
		{"X-Powered-By", "powered-by-header", []string{tomcatPoweredBy,
			"Servlet/3.1 JSP/2.3 (Apache Tomcat/9.0.100 Java/Oracle Corporation/1.8.0_452-b09)",
			"\t servlet/6.1\tjsp/4.0\t(APACHE TOMCAT/11.0.27 java/Eclipse Adoptium/21.0.8+9-LTS) \t",
		}, []string{
			"Apache Tomcat/11.0.27", "Servlet/6.1 JSP/4.0", "Java/Private Vendor/21.0.8",
			"Servlet/6.1 JSP/4.0 (Jetty/12.0.16 Java/Private Vendor/21.0.8)",
			"Servlet/6.1 JSP/4.0 (Apache Tomcat/11.0.27)",
			strings.Replace(tomcatPoweredBy, "11.0.27", "11..27", 1),
			strings.Replace(tomcatPoweredBy, "Private Vendor", "", 1),
			strings.Replace(tomcatPoweredBy, "21.0.8+9-LTS", "", 1),
			strings.Replace(tomcatPoweredBy, "Servlet/6.1", "Servlet/6..1", 1),
			strings.Replace(tomcatPoweredBy, ")", "", 1), tomcatPoweredBy + " trailing",
			tomcatPoweredBy + ", PHP/8.3", tomcatPoweredBy + "\r\n",
		}},
	} {
		for _, value := range tc.positive {
			t.Run(tc.name+"/positive/"+value, func(t *testing.T) {
				got := engine.Detect(detect.Input{Headers: http.Header{strings.ToLower(tc.name): {value, value}, strings.ToUpper(tc.name): {"unrelated"}}})
				requireTomcat(t, got, detect.Detected, tc.rule)
			})
		}
		for _, value := range tc.negative {
			t.Run(tc.name+"/negative/"+value, func(t *testing.T) {
				if got := engine.Detect(detect.Input{Headers: http.Header{tc.name: {value}}}); len(got) != 0 {
					t.Fatalf("unexpected finding: %+v", got)
				}
			})
		}
	}
}

func TestTomcatErrorRequiresStatusAndEveryMarker(t *testing.T) {
	engine := bundledEngine(t)
	for mask := 0; mask < 8; mask++ {
		for _, status := range []int{0, 200, 302, 399, 400, 404, 500, 599, 600} {
			t.Run(fmt.Sprintf("markers=%03b/status=%d", mask, status), func(t *testing.T) {
				body := ""
				for i, marker := range []string{tomcatTitle, tomcatHeading, tomcatFooter} {
					if mask&(1<<i) != 0 {
						body += marker
					}
				}
				input := detect.Input{HTTPStatus: status, HTML: []byte(body)}
				got := engine.Detect(input)
				if mask == 7 && status >= 400 && status <= 599 {
					requireTomcat(t, got, detect.Inferred, "error-report-html")
				} else if len(got) != 0 {
					t.Fatalf("partial markers or wrong status produced findings: %+v", got)
				}
				if fresh := engine.Detect(input); !reflect.DeepEqual(fresh, got) {
					t.Fatal("repeated scan changed results")
				}
				if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
					t.Fatalf("findings leaked across scans: %+v", empty)
				}
			})
		}
	}
	fixture := htmlFixture(t, "tomcat-error.html")
	requireTomcat(t, engine.Detect(detect.Input{HTTPStatus: 404, HTML: fixture}), detect.Inferred, "error-report-html")
	// Raw HTML matching can still match copied/commented examples on error responses.
	requireTomcat(t, engine.Detect(detect.Input{HTTPStatus: 404, HTML: []byte("<!--" + tomcatTitle + tomcatHeading + tomcatFooter + "-->")}), detect.Inferred, "error-report-html")
	for _, body := range []string{
		strings.Replace(string(fixture), "<title>", "<title-example>", 1),
		strings.Replace(string(fixture), "<h1>", "<h1-example>", 1),
		strings.Replace(string(fixture), "<h3>", "<h3-example>", 1),
		strings.ReplaceAll(string(fixture), "HTTP Status 404", "HTTP Status 200"),
		strings.Replace(string(fixture), "11.0.27", "11..27", 1),
		strings.Replace(string(fixture), "11.0.27", "11.0.27-M1", 1),
		strings.ReplaceAll(string(fixture), "<", "&lt;"),
	} {
		if got := engine.Detect(detect.Input{HTTPStatus: 404, HTML: []byte(body)}); len(got) != 0 {
			t.Errorf("near-miss HTML produced findings: %+v", got)
		}
	}
}

func TestTomcatEvidenceIsolationAndDirectPrecedence(t *testing.T) {
	engine := bundledEngine(t)
	body := []byte(tomcatTitle + tomcatHeading + tomcatFooter)
	for _, input := range []detect.Input{
		{HTTPStatus: 404, Headers: http.Header{"X-Example": {string(body), "Apache Tomcat/11.0.27", tomcatPoweredBy}}, CookieNames: []string{"JSESSIONID"}},
		{HTTPStatus: 404, Headers: http.Header{"X-Powered-By": {"Apache Tomcat/11.0.27"}, "Server": {tomcatPoweredBy}}},
		{HTTPStatus: 404, CookieNames: []string{"JSESSIONID", "Apache Tomcat/11.0.27"}, HTML: []byte(tomcatPoweredBy)},
		{HTTPStatus: 404, Assets: []detect.Asset{{URL: "https://example.test/app.js", Source: detect.AssetJavaScript, Body: body}, {URL: "https://example.test/app.css", Source: detect.AssetCSS, Body: body}}},
	} {
		got := engine.Detect(input)
		if len(got) != 0 {
			t.Fatalf("wrong source produced findings: %+v", got)
		}
	}
	// Independent header fields must not be concatenated into a Tomcat identity.
	split := engine.Detect(detect.Input{HTTPStatus: 404, Headers: http.Header{"Server": {"Apache ", "Tomcat/11.0.27"}}})
	if len(split) != 1 || split[0].ID != "apache" || split[0].State != detect.Detected || len(split[0].Evidence) != 1 {
		t.Fatalf("want only the standalone Apache token, got %+v", split)
	}
	input := detect.Input{HTTPStatus: 404, HTML: body, Headers: http.Header{"Server": {"Apache Tomcat/11.0.27"}, "X-Powered-By": {tomcatPoweredBy}}}
	got := engine.Detect(input)
	requireTomcat(t, got, detect.Detected, "error-report-html", "powered-by-header", "server-header")
	got[0].Evidence[0].Description = "caller mutation"
	requireTomcat(t, engine.Detect(input), detect.Detected, "error-report-html", "powered-by-header", "server-header")
	input.HTTPStatus = 200
	requireTomcat(t, engine.Detect(input), detect.Detected, "powered-by-header", "server-header")
}
