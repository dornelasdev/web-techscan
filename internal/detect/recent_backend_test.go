package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func TestRecentBackendCombinedEvidence(t *testing.T) {
	engine := bundledEngine(t)
	swagger := fastAPIFavicon + fastAPISwaggerDiv + fastAPISwaggerInit
	both := swagger + fastAPIRedocTag + fastAPIRedocScript
	for _, tc := range []struct {
		name, html, ids          string
		servers, vias, cookies   []string
		caddyState               detect.State
		caddyRules, fastapiRules []string
	}{
		{
			name: "via-with-fiber-gunicorn-and-swagger", html: swagger,
			servers: []string{"Fiber", "gunicorn", "Fiber", "gunicorn"}, vias: []string{"1.1 Caddy", "1.1 Caddy"},
			ids: "caddy fastapi fiber gunicorn", caddyState: detect.Inferred,
			caddyRules: []string{"via-header"}, fastapiRules: []string{"swagger-ui-html"},
		},
		{
			name: "caddy-upgrade-retains-via-and-both-viewers", html: both + both,
			servers: []string{"Caddy", "Fiber", "uvicorn", "Caddy"}, vias: []string{"1.1 Caddy", "2.0 Caddy"},
			ids: "caddy fastapi fiber uvicorn", caddyState: detect.Detected,
			caddyRules: []string{"server-header", "via-header"}, fastapiRules: []string{"redoc-html", "swagger-ui-html"},
		},
		{
			name: "independent-python-servers-not-a-topology", html: both,
			servers: []string{"Fiber", "gunicorn", "uvicorn"}, vias: []string{"3.0 Caddy"},
			ids: "caddy fastapi fiber gunicorn uvicorn", caddyState: detect.Inferred,
			caddyRules: []string{"via-header"}, fastapiRules: []string{"redoc-html", "swagger-ui-html"},
		},
		{
			name: "malformed-headers-do-not-block-docs", html: swagger,
			servers: []string{"Caddy/2.11.7", "Fiber-compatible", "gunicorn/23.0.0", "uvicorn/0.54.0"}, vias: []string{"1.1 Caddy, 1.1 other"},
			ids: "fastapi", fastapiRules: []string{"swagger-ui-html"},
		},
		{
			name: "viewers-cannot-borrow-favicon-from-assets", html: fastAPISwaggerDiv + fastAPISwaggerInit + fastAPIRedocTag + fastAPIRedocScript,
			servers: []string{"Fiber", "gunicorn"}, vias: []string{"1.1 Caddy"},
			ids: "caddy fiber gunicorn", caddyState: detect.Inferred, caddyRules: []string{"via-header"},
		},
		{
			name: "server-with-invalid-via-keeps-only-direct-evidence", html: swagger,
			servers: []string{"Caddy", "uvicorn"}, vias: []string{"1.1 other (Caddy)"},
			ids: "caddy fastapi uvicorn", caddyState: detect.Detected,
			caddyRules: []string{"server-header"}, fastapiRules: []string{"swagger-ui-html"},
		},
		{
			name: "partial-docs-and-django-do-not-borrow-markers", html: fastAPIFavicon,
			servers: []string{"Fiber", "uvicorn"}, vias: []string{"1.1 Caddy"}, cookies: []string{"csrftoken"},
			ids: "caddy fiber uvicorn", caddyState: detect.Inferred, caddyRules: []string{"via-header"},
		},
		{
			name: "combined-banner-is-not-independent-fields", html: swagger,
			servers: []string{"Caddy, Fiber, gunicorn, uvicorn"}, vias: []string{"1.1 Caddy, 1.1 other"},
			ids: "fastapi", fastapiRules: []string{"swagger-ui-html"},
		},
		{
			name: "python-retains-only-django-provenance", html: both + djangoInput,
			servers: []string{"Caddy", "Fiber", "uvicorn"}, vias: []string{"1.1 Caddy"}, cookies: []string{"csrftoken"},
			ids: "caddy django fastapi fiber python uvicorn", caddyState: detect.Detected,
			caddyRules: []string{"server-header", "via-header"}, fastapiRules: []string{"redoc-html", "swagger-ui-html"},
		},
		{
			name: "missing-django-cookie-is-not-supplied-by-stack", html: both + djangoInput,
			servers: []string{"Caddy", "Fiber", "uvicorn"}, vias: []string{"1.1 Caddy"},
			ids: "caddy fastapi fiber uvicorn", caddyState: detect.Detected,
			caddyRules: []string{"server-header", "via-header"}, fastapiRules: []string{"redoc-html", "swagger-ui-html"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Deliberately synthetic combinations test evidence independence,
			// not whether these technologies share an actual deployment.
			input := detect.Input{
				HTTPStatus: 403, HTML: []byte(tc.html), CookieNames: tc.cookies,
				Headers: http.Header{"Server": tc.servers, "Via": tc.vias, "X-Powered-By": {"FastAPI", "Python", "Go"}},
				Assets: []detect.Asset{
					{URL: "https://example.test/app.js", Source: detect.AssetJavaScript, Body: []byte(both + djangoInput)},
					{URL: "https://example.test/app.css", Source: detect.AssetCSS, Body: []byte(both + djangoInput)},
				},
			}
			got, ids := engine.Detect(input), []string{}
			for i, finding := range got {
				ids = append(ids, finding.ID)
				single := got[i : i+1]
				switch finding.ID {
				case "caddy":
					requireCaddy(t, single, tc.caddyState, tc.caddyRules...)
				case "fastapi":
					requireFastAPI(t, single, tc.fastapiRules...)
				case "fiber":
					requireFiber(t, single)
				case "gunicorn", "uvicorn":
					requirePythonHTTPServer(t, single, finding.ID)
				case "django":
					requireDjangoFinding(t, single)
				case "python":
					requireLanguageInference(t, single, "python", "django")
				}
			}
			if !reflect.DeepEqual(ids, strings.Fields(tc.ids)) {
				t.Fatalf("IDs=%v want=%s; findings=%+v", ids, tc.ids, got)
			}
			if fresh := engine.Detect(input); !reflect.DeepEqual(fresh, got) {
				t.Error("combined evidence changed on repeated scan")
			}
			if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
				t.Errorf("combined evidence leaked into empty scan: %+v", empty)
			}
		})
	}
}
