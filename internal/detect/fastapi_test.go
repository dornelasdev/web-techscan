package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const fastAPIFavicon = `<link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">`
const fastAPISwaggerDiv = `<div id="swagger-ui"></div>`
const fastAPISwaggerInit = `<script>const ui = SwaggerUIBundle({url: '/schema', "dom_id": "#swagger-ui", presets: [SwaggerUIBundle.presets.apis]})</script>`
const fastAPIRedocTag = `<redoc spec-url="/schema"></redoc>`
const fastAPIRedocScript = `<script src="https://cdn.jsdelivr.net/npm/redoc@2/bundles/redoc.standalone.js"></script>`

func requireFastAPI(t *testing.T, got []detect.Finding, rules ...string) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "fastapi" || got[0].Name != "FastAPI" || got[0].Category != detect.Framework || got[0].State != detect.Inferred || len(got[0].Evidence) != len(rules) {
		t.Fatalf("want only inferred FastAPI with rules %v, got %+v", rules, got)
	}
	for i, rule := range rules {
		e := got[0].Evidence[i]
		if e.RuleID != rule || !strings.Contains(e.Description, "served statically") || e.InferredFrom != "" || e.AssetURL != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.HTML}, {Source: detect.HTML}, {Source: detect.HTML}}) {
			t.Errorf("unexpected FastAPI evidence: %+v", e)
		}
	}
}

func TestFastAPIMarkerCombinations(t *testing.T) {
	engine := bundledEngine(t)
	markers := []string{fastAPIFavicon, fastAPISwaggerDiv, fastAPISwaggerInit, fastAPIRedocTag, fastAPIRedocScript}
	for mask := 0; mask < 1<<len(markers); mask++ {
		for _, status := range []int{0, 200, 403, 500} {
			t.Run(fmt.Sprintf("markers=%05b/status=%d", mask, status), func(t *testing.T) {
				body := ""
				for i, marker := range markers {
					if mask&(1<<i) != 0 {
						body += marker
					}
				}
				rules := []string{}
				if mask&0b11001 == 0b11001 {
					rules = append(rules, "redoc-html")
				}
				if mask&0b00111 == 0b00111 {
					rules = append(rules, "swagger-ui-html")
				}
				input := detect.Input{HTTPStatus: status, HTML: []byte(body + body)}
				got := engine.Detect(input)
				if len(rules) == 0 {
					if len(got) != 0 {
						t.Fatalf("partial or cross-viewer markers produced findings: %+v", got)
					}
					return
				}
				requireFastAPI(t, got, rules...)
				if fresh := engine.Detect(input); !reflect.DeepEqual(fresh, got) {
					t.Error("repeated scan changed findings")
				}
				got[0].Evidence[0].Description, got[0].Evidence[0].Signals[0].Name = "caller mutation", "changed"
				requireFastAPI(t, engine.Detect(input), rules...)
				if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
					t.Errorf("findings retained across scans: %+v", empty)
				}
			})
		}
	}
}

func TestFastAPIHTMLBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct{ name, viewer, rule string }{
		{"swagger", fastAPISwaggerDiv + fastAPISwaggerInit, "swagger-ui-html"},
		{"redoc", fastAPIRedocTag + fastAPIRedocScript, "redoc-html"},
	} {
		for _, icon := range []string{
			fastAPIFavicon,
			`<LINK data-first='fixture' HREF = 'HTTPS://FASTAPI.TIANGOLO.COM/img/favicon.png' data-middle=fixture REL = 'SHORTCUT ICON' disabled />`,
		} {
			requireFastAPI(t, engine.Detect(detect.Input{HTML: []byte(icon + tc.viewer)}), tc.rule)
		}
		for _, url := range []string{
			"https://fastapi.tiangolo.com.evil.test/img/favicon.png", "https://evil.test/fastapi.tiangolo.com/img/favicon.png",
			"https://fastapi.tiangolo.com@evil.test/img/favicon.png", "https://fastapi.tiangolo.com:443/img/favicon.png",
			"http://fastapi.tiangolo.com/img/favicon.png", "//fastapi.tiangolo.com/img/favicon.png",
			"https://fastapi.tiangolo.com/IMG/favicon.png", "https://fastapi.tiangolo.com/img/favicon.png-extra",
			"https://fastapi.tiangolo.com/img/favicon.png?copy=1", "https://fastapi.tiangolo.com/img/favicon.png#copy",
			"https://fastapi.tiangolo.com/img/favicon.png\n", "https://faſtapi.tiangolo.com/img/favicon.png",
		} {
			icon := strings.Replace(fastAPIFavicon, "https://fastapi.tiangolo.com/img/favicon.png", url, 1)
			if got := engine.Detect(detect.Input{HTML: []byte(icon + tc.viewer)}); len(got) != 0 {
				t.Errorf("favicon URL lookalike %q produced %+v", url, got)
			}
		}
		for _, icon := range []string{
			`<link rel="shortcut icon" data-href="https://fastapi.tiangolo.com/img/favicon.png">`,
			`<link data-rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">`,
			`<link rel="stylesheet" href="https://fastapi.tiangolo.com/img/favicon.png">`,
			`<link rel="shortcut icon"><link href="https://fastapi.tiangolo.com/img/favicon.png">`,
			`<a rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">`,
			`<link rel="shortcut icon" data-example='href="https://fastapi.tiangolo.com/img/favicon.png"'>`,
			`<link href="https://fastapi.tiangolo.com/img/favicon.png" data-example='rel="shortcut icon"'>`,
			`<link rel=shortcut href="https://fastapi.tiangolo.com/img/favicon.png">`,
			strings.TrimSuffix(fastAPIFavicon, ">"),
			strings.Replace(fastAPIFavicon, "link ", "link-widget ", 1),
			strings.Replace(fastAPIFavicon, "link ", "linK ", 1),
			strings.Replace(fastAPIFavicon, "shortcut", "ſhortcut", 1),
			strings.ReplaceAll(strings.ReplaceAll(fastAPIFavicon, "<", "&lt;"), ">", "&gt;"),
			`<title>FastAPI - Swagger UI</title>`,
		} {
			if got := engine.Detect(detect.Input{HTML: []byte(icon + tc.viewer)}); len(got) != 0 {
				t.Errorf("incomplete/decoy favicon markup %q produced %+v", icon, got)
			}
		}
	}
	for _, tc := range []struct{ file, rule string }{{"fastapi-swagger.html", "swagger-ui-html"}, {"fastapi-redoc.html", "redoc-html"}} {
		fixture := htmlFixture(t, tc.file)
		requireFastAPI(t, engine.Detect(detect.Input{HTML: fixture}), tc.rule)
		// Copied/commented markup can match raw HTML; neither establishes execution.
		requireFastAPI(t, engine.Detect(detect.Input{HTML: []byte("<!--" + string(fixture) + "-->")}), tc.rule)
	}
	for _, viewer := range []string{
		strings.Replace(fastAPISwaggerDiv, `id=`, `data-id=`, 1) + fastAPISwaggerInit,
		strings.Replace(fastAPISwaggerDiv, "swagger-ui", "swagger-ui-other", 1) + fastAPISwaggerInit,
		strings.Replace(fastAPISwaggerDiv, "div ", "span ", 1) + fastAPISwaggerInit,
		fastAPISwaggerDiv + strings.Replace(fastAPISwaggerInit, "SwaggerUIBundle", "swaggerUIBundle", 1),
		fastAPISwaggerDiv + strings.ReplaceAll(fastAPISwaggerInit, "script", "ſcript"),
		fastAPISwaggerDiv + strings.Replace(fastAPISwaggerInit, "#swagger-ui", "#other", 1),
		fastAPISwaggerDiv + strings.Replace(fastAPISwaggerInit, "'/schema'", "''", 1),
		fastAPISwaggerDiv + strings.Replace(fastAPISwaggerInit, `"dom_id"`, `"data-dom_id"`, 1),
		fastAPISwaggerDiv + strings.Replace(fastAPISwaggerInit, `"dom_id"`, `</script><script>"dom_id"`, 1),
		fastAPISwaggerDiv + strings.TrimSuffix(fastAPISwaggerInit, "</script>"),
		strings.Replace(fastAPIRedocTag, "spec-url", "data-spec-url", 1) + fastAPIRedocScript,
		strings.Replace(fastAPIRedocTag, "spec-url", "ſpec-url", 1) + fastAPIRedocScript,
		strings.Replace(fastAPIRedocTag, "/schema", "", 1) + fastAPIRedocScript,
		strings.Replace(fastAPIRedocTag, "redoc ", "redoc-widget ", 1) + fastAPIRedocScript,
		fastAPIRedocTag + strings.Replace(fastAPIRedocScript, "src=", "data-src=", 1),
		fastAPIRedocTag + strings.Replace(fastAPIRedocScript, "cdn.jsdelivr.net", "cdn.jsdelivr.net.evil.test", 1),
		fastAPIRedocTag + strings.Replace(fastAPIRedocScript, "jsdelivr", "jſdelivr", 1),
		fastAPIRedocTag + strings.Replace(fastAPIRedocScript, "redoc@2", "redoc@3", 1),
		fastAPIRedocTag + strings.Replace(fastAPIRedocScript, ".js", ".js.map", 1),
		fastAPIRedocTag + strings.TrimSuffix(fastAPIRedocScript, "</script>"),
	} {
		if got := engine.Detect(detect.Input{HTML: []byte(fastAPIFavicon + viewer)}); len(got) != 0 {
			t.Errorf("incomplete/decoy viewer markup produced %+v: %s", got, viewer)
		}
	}
	for _, viewer := range []struct{ html, rule string }{
		{`<DIV data-first='fixture' ID='swagger-ui' ></DIV>` + `<SCRIPT >const ui=SwaggerUIBundle({url:"/prefix/schema.json?x=1",'dom_id':'#swagger-ui',layout:'BaseLayout'});</SCRIPT>`, "swagger-ui-html"},
		{`<REDOC data-first='fixture' SPEC-URL='/prefix/schema.json?x=1' ></REDOC><SCRIPT defer SRC='HTTPS://CDN.JSDELIVR.NET/npm/redoc@next/bundles/redoc.standalone.js' ></SCRIPT>`, "redoc-html"},
	} {
		requireFastAPI(t, engine.Detect(detect.Input{HTML: []byte(fastAPIFavicon + viewer.html)}), viewer.rule)
	}
}

func TestFastAPISourceAndBackendIsolation(t *testing.T) {
	engine := bundledEngine(t)
	docs := fastAPIFavicon + fastAPISwaggerDiv + fastAPISwaggerInit + fastAPIRedocTag + fastAPIRedocScript
	for _, input := range []detect.Input{
		{Headers: http.Header{"X-Example": {docs}, "X-Powered-By": {"FastAPI"}, "Server": {"uvicorn"}}, CookieNames: []string{"FastAPI", "session"}},
		{HTTPStatus: 404, Headers: http.Header{"Server": {"Werkzeug/3.1.3 Python/3.13.0"}, "Vary": {"Cookie"}}, CookieNames: []string{"session"}, HTML: []byte(`<title>404 Not Found</title>{"detail":"Not Found"}`)},
		{Assets: []detect.Asset{{URL: "https://example.test/docs.js", Source: detect.AssetJavaScript, Body: []byte(docs)}, {URL: "https://example.test/docs.css", Source: detect.AssetCSS, Body: []byte(docs)}}},
		{HTML: []byte(fastAPIFavicon), Assets: []detect.Asset{{URL: "https://example.test/docs.js", Source: detect.AssetJavaScript, Body: []byte(docs)}}},
		{HTML: []byte(fastAPISwaggerDiv + fastAPISwaggerInit + fastAPIRedocTag + fastAPIRedocScript), Headers: http.Header{"X-Example": {fastAPIFavicon}}},
	} {
		if got := engine.Detect(input); len(got) != 0 {
			t.Errorf("wrong-source/generic evidence produced findings: %+v", got)
		}
	}
	for mask := 0; mask < 4; mask++ {
		input := detect.Input{Headers: http.Header{"Server": {"nginx"}}, HTML: []byte(docs)}
		if mask&1 != 0 {
			input.CookieNames = []string{"csrftoken"}
		}
		if mask&2 != 0 {
			input.HTML = append(input.HTML, djangoInput...)
		}
		want := []string{"fastapi", "nginx"}
		if mask == 3 {
			want = append(want, "django", "python")
		}
		sort.Strings(want)
		got, ids := engine.Detect(input), []string{}
		for i, f := range got {
			ids = append(ids, f.ID)
			switch f.ID {
			case "fastapi":
				requireFastAPI(t, got[i:i+1], "redoc-html", "swagger-ui-html")
			case "django":
				requireDjangoFinding(t, got[i:i+1])
			case "python":
				requireLanguageInference(t, got[i:i+1], "python", "django")
			}
		}
		if !reflect.DeepEqual(ids, want) {
			t.Fatalf("findings=%+v want=%v; Python must retain Django-only provenance", got, want)
		}
	}
}
