package detect_test

import (
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func bundledEngine(t *testing.T) *detect.Engine {
	t.Helper()
	engine, err := detect.LoadBundled()
	if err != nil {
		t.Fatal(err)
	}
	return engine
}

func htmlFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/coverage/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestBundledHeaderFingerprints(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct {
		id, header, rule   string
		category           detect.Category
		positive, negative []string
	}{
		{"nginx", "Server", "server-header", detect.WebServer,
			[]string{"nginx", "nginx/1.26.2", "NGINX/1.24.0 (Ubuntu)", " nginx \t"},
			[]string{"not-nginx", "nginx-proxy", "nginxish", "openresty/1.25.3.1", "nginx/", "cloudflare"}},
		{"apache", "Server", "server-header", detect.WebServer,
			[]string{"Apache", "Apache/2", "Apache/2.4.62 (Unix) OpenSSL/3.0.0", " apache/2.4.62 "},
			[]string{"Apache-Coyote/1.1", "ApacheTrafficServer/9.0", "NotApache", "Apache/", "my Apache proxy"}},
		{"iis", "Server", "server-header", detect.WebServer,
			[]string{"Microsoft-IIS", "Microsoft-IIS/10.0", " microsoft-iis/7.5 "},
			[]string{"Microsoft-HTTPAPI/2.0", "Microsoft-IISish", "Microsoft-IIS/", "Microsoft-IIS/10.0other", "Kestrel"}},
		{"express", "X-Powered-By", "powered-by-header", detect.Framework,
			[]string{"Express", " express\t"},
			[]string{"Expressive", "NotExpress", "Express/5", "my Express app"}},
		{"nextjs", "X-Powered-By", "powered-by-header", detect.Framework,
			[]string{"Next.js", " NEXT.JS "},
			[]string{"NextXjs", "Next.js-compatible", "NotNext.js", "Next.js/15"}},
		{"php", "X-Powered-By", "powered-by-header", detect.Language,
			[]string{"PHP", "PHP/8.3.12", "PHP/8.4.0RC1", "PHP/8.2.20-1+deb12u1", " php/8.3.12 "},
			[]string{"PHPish", "NotPHP", "PHP/", "HHVM/4.0", "PHP framework"}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			for _, value := range tc.positive {
				t.Run("positive/"+value, func(t *testing.T) {
					got := engine.Detect(detect.Input{Headers: http.Header{strings.ToLower(tc.header): {value}}})
					if len(got) != 1 || got[0].ID != tc.id || got[0].State != detect.Detected || got[0].Category != tc.category {
						t.Fatalf("findings=%+v, want only detected %s", got, tc.id)
					}
					if len(got[0].Evidence) != 1 || got[0].Evidence[0].RuleID != tc.rule {
						t.Errorf("unexpected rule evidence: %+v", got[0].Evidence)
					}
				})
			}
			for _, value := range tc.negative {
				t.Run("near-miss/"+value, func(t *testing.T) {
					if got := engine.Detect(detect.Input{Headers: http.Header{tc.header: {value}}}); len(got) != 0 {
						t.Fatalf("unexpected findings: %+v", got)
					}
				})
			}
		})
	}
}

func TestLaravelCookieInference(t *testing.T) {
	engine := bundledEngine(t)
	for _, directPHP := range []bool{false, true} {
		headers := make(http.Header)
		if directPHP {
			headers.Set("X-Powered-By", "PHP/8.3.12")
		}
		got := engine.Detect(detect.Input{Headers: headers, CookieNames: []string{"XSRF-TOKEN", "laravel_session"}})
		if len(got) != 2 || got[0].ID != "laravel" || got[1].ID != "php" {
			t.Fatalf("findings=%+v, want Laravel and PHP", got)
		}
		if got[0].State != detect.Inferred || got[0].Evidence[0].RuleID != "default-cookie-pair" {
			t.Errorf("cookie combination should infer Laravel: %+v", got[0])
		}
		wantPHP := detect.Inferred
		if directPHP {
			wantPHP = detect.Detected
		}
		if got[1].State != wantPHP {
			t.Errorf("PHP state=%s, want %s", got[1].State, wantPHP)
		}
		evidence := got[1].Evidence
		if evidence[len(evidence)-1].InferredFrom != "laravel" {
			t.Errorf("missing inference source: %+v", evidence)
		}
	}
	for _, names := range [][]string{
		{"laravel_session"}, {"XSRF-TOKEN"}, {"custom_session", "XSRF-TOKEN"},
		{"laravel_session_extra", "XSRF-TOKEN"}, {"laravel_session", "XSRF-TOKEN-extra"},
		{"Laravel_session", "XSRF-TOKEN"}, {"PHPSESSID"}, {"sessionid", "csrftoken"}, {"connect.sid"},
	} {
		if got := engine.Detect(detect.Input{CookieNames: names}); len(got) != 0 {
			t.Errorf("cookies %v produced unsupported findings: %+v", names, got)
		}
	}
}

func TestNextHTMLInference(t *testing.T) {
	engine := bundledEngine(t)
	for _, file := range []string{"next-pages.html", "next-cdn.html"} {
		t.Run(file, func(t *testing.T) {
			body := htmlFixture(t, file)
			got := engine.Detect(detect.Input{HTML: body})
			if len(got) != 1 || got[0].ID != "nextjs" || got[0].State != detect.Inferred {
				t.Fatalf("findings=%+v, want Next.js inference without language guesses", got)
			}
			if got[0].Evidence[0].RuleID != "pages-html-markers" || len(got[0].Evidence[0].Signals) != 2 {
				t.Errorf("missing combined HTML evidence: %+v", got[0].Evidence)
			}
			got = engine.Detect(detect.Input{HTML: body, Headers: http.Header{"X-Powered-By": {"Next.js"}}})
			if len(got) != 1 || got[0].State != detect.Detected || len(got[0].Evidence) != 2 {
				t.Errorf("direct header should retain both rules and detected state: %+v", got)
			}
		})
	}
	dataScript := `<script id="__NEXT_DATA__" type="application/json">{}</script>`
	assetScript := `<script src="/_next/static/chunks/main.js"></script>`
	for _, body := range []string{
		dataScript, assetScript,
		`<p>__NEXT_DATA__ /_next/static/chunks/main.js</p>`,
		dataScript + `<script data-src="/_next/static/chunks/main.js"></script>`,
		`<script data-id="__NEXT_DATA__"></script>` + assetScript,
		`<script id="__NEXT_DATA__-other"></script>` + assetScript,
		dataScript + `<script src="/_next/staticish/chunks/main.js"></script>`,
		dataScript + `<script src="/proxy?path=/_next/static/chunks/main.js"></script>`,
		dataScript + `<script src="/main.js#/_next/static/chunks/main.js"></script>`,
		dataScript + `<script src="/_NEXT/static/chunks/main.js"></script>`,
		`&lt;script id="__NEXT_DATA__"&gt;&lt;/script&gt;` + assetScript,
	} {
		if got := engine.Detect(detect.Input{HTML: []byte(body)}); len(got) != 0 {
			t.Errorf("HTML %q produced unsupported findings: %+v", body, got)
		}
	}
}

func TestBundledMixedStack(t *testing.T) {
	engine := bundledEngine(t)
	got := engine.Detect(detect.Input{
		Headers:     http.Header{"Server": {"nginx/1.26.2"}, "X-Powered-By": {"unrelated", "PHP/8.3.12"}},
		CookieNames: []string{"laravel_session", "XSRF-TOKEN"},
	})
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
	}
	if !reflect.DeepEqual(ids, []string{"laravel", "nginx", "php"}) {
		t.Errorf("mixed stack IDs=%v", ids)
	}
	if got := engine.Detect(detect.Input{}); len(got) != 0 {
		t.Errorf("findings leaked between scans: %+v", got)
	}
}
