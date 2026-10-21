package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func TestServerBannerBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct {
		id                 string
		positive, negative []string
	}{
		{"apache", []string{
			"Apache", "Apache/2", "Apache/2.4", "Apache/2.4.62",
			"Apache (Unix)", " Apache\t(private build) ",
			"Apache/2.4.62 (Unix)", "Apache/2.4.62 (Unix) PHP/8.3.12 MyMod/1.2",
			"Apache/2.4.62 (Debian) OpenSSL/3.0.0 mod_perl/2.0.12 Perl/v5.36.0",
			"Apache/2.4.62-dev", "Apache/2.4.62-dev (Unix) MyMod/0.1-alpha",
			"Apache/2.4.62 mod_ssl/2.4.62 (private build)",
			"\t aPaChE/2.4.62\t(Unix)\tOpenSSL/1.1.1w \t",
		}, []string{
			"Apache/2..4", "Apache/2.", "Apache/.2", "Apache/2garbage",
			"Apache/2.4.62-compatible", "Apache/2.4.62-dev-extra", "Apache/dev",
			"Apache is not the server", "Apache/2.4.62 proxy", "Apache/2.4.62 <fake>",
			"Apache/2.4.62 (Unix", "Apache/2.4.62 Unix)", "Apache/2.4.62 (Unix)garbage",
			"Apache/2.4.62(Unix)", "Apache/2.4.62 OpenSSL/", "Apache/2.4.62 OpenSSL/3/extra",
			"Apache/2.4.62, nginx", "Apache/2.4.62 , nginx", "proxy Apache/2.4.62",
			"Apache/2.4.62 ((nested))", `Apache/2.4.62 (escaped\)comment)`,
			"Apache/2.4.62 (café)", "Apache/2.4.62 (K)", "Apache/2.4.62 OpenſSL/3.0",
			"Apache/2.4.62\n", "Apache/2.4.62 (bad\x00value)",
			"Apache PHP/8.3.12", "Apache MyMod/1.2", "Apache (Unix) PHP/8.3.12", "Apache Tomcat/11..27",
		}},
		{"nginx", []string{
			"nginx", "nginx/1.26.2", "NGINX/1.24.0 (Ubuntu)", " nginx \t",
			"nginx/1.26.2 (private build 123)", "nginx/1.26.2 (custom-nginx/0.1)",
			"\tnginx/1.26.2\t(build; branch=stable)\t",
		}, []string{
			"nginx/1..2", "nginx/1.", "nginx/.1", "nginx/1garbage",
			"nginx/1.26.2-compatible", "nginx/1.26.2-1+custom", "nginx/stable",
			"nginx is not the server", "nginx/1.26.2 proxy", "nginx/1.26.2 <fake>",
			"nginx/1.26.2 (Ubuntu", "nginx/1.26.2 Ubuntu)", "nginx/1.26.2 (Ubuntu)extra",
			"nginx/1.26.2(Ubuntu)", "nginx/1.26.2 (one) (two)", "nginx/1.26.2 PHP/8.3",
			"nginx/1.26.2, Apache", "nginx/1.26.2 , Apache", "proxy nginx/1.26.2",
			"nginx/1.26.2 ((nested))", `nginx/1.26.2 (escaped\)comment)`,
			"nginx/1.26.2 (café)", "nginx/1.26.2 (K)",
			"nginx/1.26.2\r\n", "nginx/1.26.2 (bad\x7fvalue)",
		}},
		{"gunicorn", []string{
			"gunicorn", "GUNICORN", "Gunicorn", "\t gUnIcOrN \t",
		}, []string{
			"", "Guni", "corn", "Guni corn", "Guni\tcorn", "gunicorn/23.0.0", "gunicorn/26.2.2",
			"gunicorn/19.9.0", "Gunicorn()", "Gunicorn (Python)", "Gunicorn proxy", "proxy Gunicorn",
			"NotGunicorn", "Gunicorn-compatible", "GunicornHTTP", "gunicorn, uvicorn", "uvicorn, gunicorn",
			"GunicornGunicorn", "Gunicorn\n", "Gunicorn\r\n", "Gunicorn\x00", "Gunicorn\x7f", "\vGunicorn", "\fGunicorn",
			"\u00a0Gunicorn", "Gunicorn\u00a0", "Ｇunicorn", "Gunіcorn", "GunicornK",
		}},
		{"uvicorn", []string{
			"uvicorn", "UVICORN", "Uvicorn", "\t uViCoRn \t",
		}, []string{
			"", "Uvi", "corn", "Uvi corn", "Uvi\tcorn", "uvicorn/0.35.0", "uvicorn/0.54.0",
			"Uvicorn()", "Uvicorn (Python)", "Uvicorn proxy", "proxy Uvicorn", "NotUvicorn",
			"Uvicorn-compatible", "UvicornWorker", "UvicornHTTP", "uvicorn, gunicorn", "gunicorn, uvicorn",
			"UvicornUvicorn", "Uvicorn\n", "Uvicorn\r\n", "Uvicorn\x00", "Uvicorn\x7f", "\vUvicorn", "\fUvicorn",
			"\u00a0Uvicorn", "Uvicorn\u00a0", "Ｕvicorn", "Uvіcorn", "UvicornK",
		}},
		{"iis", []string{
			"Microsoft-IIS", "Microsoft-IIS/6.0", "Microsoft-IIS/7.5", "Microsoft-IIS/10.0",
			"\t mIcRoSoFt-IiS/10.0 \t",
		}, []string{
			"Microsoft-IIS/10..0", "Microsoft-IIS/10.", "Microsoft-IIS/.10", "Microsoft-IIS/10other",
			"Microsoft-IIS/10.0-compatible", "Microsoft-IIS/10.0 (Windows)",
			"Microsoft-IIS/10.0 proxy", "Microsoft-IIS/10.0, nginx", "proxy Microsoft-IIS/10.0",
			"Microsoft-IIS/10.0\n", "Microsoft-IIS/10.0\x00", "Microsoft-HTTPAPI/2.0", "Kestrel-compatible",
		}},
		{"kestrel", []string{
			"Kestrel", "kestrel", "KESTREL", "\t kEsTrEl \t",
		}, []string{
			"", "Kes", "trel", "Kes trel", "Kes\ttrel", "Kestrel/8.0", "Kestrel/10.0.0",
			"Kestrel()", "Kestrel (Unix)", "Kestrel proxy", "proxy Kestrel", "NotKestrel",
			"Kestrel-compatible", "KestrelHTTP", "Kestrel, nginx", "nginx, Kestrel", "KestrelKestrel",
			"Kestrel\n", "Kestrel\r\n", "Kestrel\x00", "Kestrel\x7f", "\vKestrel", "\fKestrel",
			"\u00a0Kestrel", "Kestrel\u00a0", "Kestrel", "Keſtrel", "Ｋestrel",
		}},
		{"litespeed", []string{
			"LiteSpeed", "litespeed", "LITESPEED", "\t lItEsPeEd \t",
			"LiteSpeed/1.8.4 Open", "LiteSpeed/1.9.3 Open", "\t lItEsPeEd/1.9.3\t oPeN \t",
		}, []string{
			"", "Lite", "Speed", "Lite Speed", "Lite\tSpeed", "LiteSpeedOpen", "OpenLiteSpeed",
			"LiteSpeed Open", "LiteSpeed/1.9.3", "LiteSpeed/6.3.4 Enterprise", "LiteSpeed/1.9.3 (Open)",
			"LiteSpeed/1 Open", "LiteSpeed/1.9 Open", "LiteSpeed/1.9.0.1 Open", "LiteSpeed/1..3 Open",
			"LiteSpeed/.9.3 Open", "LiteSpeed/1.9. Open", "LiteSpeed/1.9.3Open", "LiteSpeed /1.9.3 Open",
			"LiteSpeed/v1.9.3 Open", "LiteSpeed/1.9.3-rc1 Open", "LiteSpeed/1.9.3 OpenSSL",
			"LiteSpeed/1.9.3 Open-compatible", "LiteSpeed/1.9.3 Open proxy", "LiteSpeed-compatible",
			"NotLiteSpeed", "LiteSpeedHTTP", "LiteSpeedLiteSpeed", "LiteSpeed (Unix)", "proxy LiteSpeed",
			"LiteSpeed, nginx", "nginx, LiteSpeed", "LiteSpeed/1.9.3 Open, nginx",
			"LiteSpeed\n", "LiteSpeed/1.9.3\nOpen", "LiteSpeed/1.9.3 Open\r\n", "LiteSpeed\x00", "LiteSpeed\x7f",
			"\vLiteSpeed", "\fLiteSpeed", "LiteSpeed/1.9.3\vOpen", "LiteSpeed/1.9.3\fOpen",
			"\u00a0LiteSpeed", "LiteSpeed\u00a0", "LiteSpeed/1.9.3\u00a0Open", "LiteSpeed/１.9.3 Open",
			"ＬiteSpeed", "Liteſpeed", "LіteSpeed", "LiteSpeed/1.9.3 Оpen",
		}},
		{"openresty", []string{
			"openresty", "OpenResty", "OPENRESTY", "\t oPeNrEsTy \t",
			"openresty/1.25.3.1", "openresty/1.25.3.2", "openresty/1.27.1.2", "\t oPeNrEsTy/1.27.1.2 \t",
		}, []string{
			"", "open", "resty", "open resty", "open\tresty", "openresty/", "openresty/1", "openresty/1.27",
			"openresty/1.27.1", "openresty/1.27.1.2.3", "openresty/1..1.2", "openresty/.27.1.2",
			"openresty/1.27.1.", "openresty/1.27.1.unknown", "openresty/1.27.1.2rc1", "openresty/1.27.1.2-dev",
			"openresty/1.27.1.2-compatible", "openresty/1.27.1.2 (custom)", "openresty (custom)",
			"openresty /1.27.1.2", "openresty/ 1.27.1.2", "NotOpenResty", "openresty-proxy", "openrestyish",
			"openresty/1.27.1.2 proxy", "proxy openresty", "openresty, nginx", "nginx, openresty",
			"openrestyopenresty", "openresty\n", "openresty/1.27.1.2\r\n", "openresty\x00", "openresty\x7f",
			"\vopenresty", "\fopenresty", "\u00a0openresty", "openresty\u00a0", "openresty/１.27.1.2",
			"ＯpenResty", "openreſty", "оpenresty", "openrestу",
		}},
		{"jetty", []string{
			"Jetty(12.0.16)", "Jetty(10.0.24)", "Jetty(11.0.24)",
			"Jetty(9.4.57.v20241219)", "Jetty(9.4.57)", "\t jEtTy(12.0.16) \t",
		}, []string{
			"", "Jetty", "Jetty/12.0.16", "Jetty()", "Jetty(12)", "Jetty(12.0)",
			"Jetty(12.0.16.1)", "Jetty(12..16)", "Jetty(.0.16)", "Jetty(12.0.16.)",
			"Jetty(12.0.16", "Jetty12.0.16)", "Jetty((12.0.16))", "Jetty (12.0.16)",
			"Jetty( 12.0.16)", "Jetty(12.0.16 )", "Jetty(12.0.16\t)",
			"Jetty(9.4.57.v2024121)", "Jetty(9.4.57.v202412190)", "Jetty(9.4.57.V20241219)",
			"Jetty(9.4.57.v2024abcd)", "Jetty(9.4.57.v20241219.extra)",
			"Jetty(12.0.16-SNAPSHOT)", "Jetty(12.0.16.RC1)", "Jetty(12.0.16-custom)",
			"Jetty(12.0.16) proxy", "Jetty(12.0.16) (Unix)", "proxy Jetty(12.0.16)",
			"Jetty(12.0.16), nginx", "nginx, Jetty(12.0.16)", "Jetty(12.0.16)Jetty(12.0.16)",
			"NotJetty(12.0.16)", "Jetty-compatible(12.0.16)", "jetty-http/12.0.16",
			"Jetty(１２.0.16)", "Jetty(12.0.16)\n", "Jetty(12.0.16)\r\n",
			"Jetty(12.0.16)\x00", "Jetty(12.0.16)\x7f", "\u00a0Jetty(12.0.16)",
		}},
	} {
		for _, value := range tc.positive {
			t.Run(tc.id+"/positive/"+value, func(t *testing.T) {
				// Repeated fields and mixed header-name casing must not duplicate evidence.
				got := engine.Detect(detect.Input{Headers: http.Header{"server": {"unrelated", value}, "SERVER": {value}}})
				if len(got) != 1 || got[0].ID != tc.id || got[0].Category != detect.WebServer || got[0].State != detect.Detected {
					t.Fatalf("findings=%+v, want only detected %s", got, tc.id)
				}
				evidence := got[0].Evidence
				if len(evidence) != 1 || evidence[0].RuleID != "server-header" || evidence[0].InferredFrom != "" || !strings.Contains(evidence[0].Description, "may be an intermediary") || !reflect.DeepEqual(evidence[0].Signals, []detect.Signal{{Source: detect.Header, Name: "Server"}}) {
					t.Errorf("unexpected evidence: %+v", evidence)
				}
			})
		}
		for _, value := range tc.negative {
			t.Run(tc.id+"/negative/"+value, func(t *testing.T) {
				if got := engine.Detect(detect.Input{Headers: http.Header{"Server": {value}}}); len(got) != 0 {
					t.Fatalf("unexpected findings: %+v", got)
				}
			})
		}
	}
}

func TestServerEvidenceIsolation(t *testing.T) {
	engine := bundledEngine(t)
	for _, banner := range []string{"nginx/1.26.2", "Apache/2.4.62", "Caddy", "gunicorn", "Microsoft-IIS/10.0", "Jetty(12.0.16)", "Jetty(9.4.57.v20241219)", "Kestrel", "LiteSpeed", "LiteSpeed/1.9.3 Open", "Apache Tomcat/11.0.27", "openresty", "openresty/1.27.1.2", "uvicorn"} {
		for _, input := range []detect.Input{
			{Headers: http.Header{"Via": {banner}, "X-Powered-By": {banner}, "X-Server": {banner}}},
			{HTML: []byte("<footer>" + banner + "</footer>"), CookieNames: []string{banner}},
			{Assets: []detect.Asset{
				{URL: "https://example.test/app.js", Source: detect.AssetJavaScript, Body: []byte(banner)},
				{URL: "https://example.test/app.css", Source: detect.AssetCSS, Body: []byte(banner)},
			}},
		} {
			if got := engine.Detect(input); len(got) != 0 {
				t.Errorf("wrong-source banner %q yielded %+v", banner, got)
			}
		}
	}
	// Independent fields are not concatenated, nor interpreted as a proxy chain.
	got := engine.Detect(detect.Input{Headers: http.Header{"Server": {"nginx", "Apache/2.4.62", "Caddy", "CADDY", "gunicorn", "GUNICORN", "Microsoft-IIS/10.0", "Jetty(12.0.16)", "Jetty(9.4.57.v20241219)", "Kestrel", "KESTREL", "LiteSpeed", "LiteSpeed/1.8.4 Open", "Apache Tomcat/11.0.27", "uvicorn", "UVICORN", "openresty", "openresty/1.27.1.2", "nginx"}}})
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
		if len(finding.Evidence) != 1 {
			t.Errorf("duplicate evidence: %+v", finding)
		}
	}
	if !reflect.DeepEqual(ids, []string{"apache", "caddy", "gunicorn", "iis", "jetty", "kestrel", "litespeed", "nginx", "openresty", "tomcat", "uvicorn"}) {
		t.Fatalf("IDs=%v, want independent server findings without language guesses", ids)
	}
	if got := engine.Detect(detect.Input{Headers: http.Header{"Server": {"Apache/", "2.4.62", "nginx/", "1.26.2", "Microsoft-IIS/", "10.0", "Jetty(", "12.0.16)", "Jetty(9.4.57.", "v20241219)", "Lite", "Speed", "LiteSpeed/", "1.9.3 Open", "LiteSpeed/1.9.3", "Open", "Kes", "trel", "Guni", "Uvi", "corn"}}}); len(got) != 0 {
		t.Errorf("split values combined into findings: %+v", got)
	}
}
