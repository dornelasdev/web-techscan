package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func requireOpenResty(t *testing.T, got []detect.Finding) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "openresty" || got[0].Name != "OpenResty" || got[0].Category != detect.WebServer || got[0].State != detect.Detected || len(got[0].Evidence) != 1 {
		t.Fatalf("want only detected OpenResty without nginx/language implications, got %+v", got)
	}
	e := got[0].Evidence[0]
	if e.RuleID != "server-header" || e.Description != "Server header reports OpenResty; this may be an intermediary" || e.InferredFrom != "" || e.AssetURL != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.Header, Name: "Server"}}) {
		t.Errorf("unexpected OpenResty evidence: %+v", e)
	}
}

func TestOpenRestyStatusAndReuse(t *testing.T) {
	engine := bundledEngine(t)
	for _, banner := range []string{"openresty", "openresty/1.25.3.2", "openresty/1.27.1.2"} {
		for _, status := range []int{0, 200, 403, 500} {
			t.Run(fmt.Sprintf("%s/status=%d", banner, status), func(t *testing.T) {
				input := detect.Input{HTTPStatus: status, Headers: http.Header{"server": {banner, banner}, "SERVER": {banner}}}
				got := engine.Detect(input)
				requireOpenResty(t, got)
				if fresh := engine.Detect(input); !reflect.DeepEqual(fresh, got) {
					t.Error("repeated scan changed findings")
				}
				got[0].Evidence[0].Description, got[0].Evidence[0].Signals[0].Name = "caller mutation", "changed"
				requireOpenResty(t, engine.Detect(input))
				if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
					t.Errorf("findings leaked across scans: %+v", empty)
				}
			})
		}
	}
}

func TestOpenRestySourceIsolationAndIndependentStack(t *testing.T) {
	engine := bundledEngine(t)
	for _, banner := range []string{"openresty", "openresty/1.27.1.2"} {
		for _, input := range []detect.Input{
			{Headers: http.Header{"X-Server": {banner}, "X-Powered-By": {banner}, "X-OpenResty": {banner}, "Via": {banner}}},
			{Headers: http.Header{"Server": {"open", "resty", "openresty/", "1.27.1.2", "openresty/1.27.1.", "2"}}},
			{HTTPStatus: 403, CookieNames: []string{"openresty", "lua"}, HTML: []byte("<h1>403 Forbidden</h1><hr><center>" + banner + "</center>")},
			{Assets: []detect.Asset{
				{URL: "https://example.test/app.js", Source: detect.AssetJavaScript, Body: []byte(banner)},
				{URL: "https://example.test/app.css", Source: detect.AssetCSS, Body: []byte(banner)},
			}},
		} {
			if got := engine.Detect(input); len(got) != 0 {
				t.Errorf("wrong-source or split evidence yielded %+v", got)
			}
		}
	}
	for _, tc := range []struct {
		name, html, ids  string
		servers, cookies []string
	}{
		{name: "openresty-alone", servers: []string{"openresty/1.27.1.2"}, ids: "openresty"},
		{name: "nginx-alone", servers: []string{"nginx/1.26.2"}, ids: "nginx"},
		{name: "independent-server-fields", servers: []string{"nginx", "openresty", "nginx", "openresty/1.27.1.2"}, ids: "nginx openresty"},
		{name: "combined-field-is-not-two-findings", servers: []string{"nginx, openresty"}},
		{name: "django-only-python-provenance", servers: []string{"nginx", "openresty"}, html: djangoInput, cookies: []string{"csrftoken"}, ids: "django nginx openresty python"},
		{name: "partial-framework-is-not-completed-by-server", servers: []string{"nginx", "openresty"}, html: djangoInput, ids: "nginx openresty"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Detect(detect.Input{Headers: http.Header{"Server": tc.servers}, HTML: []byte(tc.html), CookieNames: tc.cookies})
			ids := []string{}
			for i, f := range got {
				ids = append(ids, f.ID)
				switch f.ID {
				case "openresty":
					requireOpenResty(t, got[i:i+1])
				case "nginx":
					if f.State != detect.Detected || len(f.Evidence) != 1 || f.Evidence[0].RuleID != "server-header" || f.Evidence[0].InferredFrom != "" || f.Evidence[0].AssetURL != "" || !reflect.DeepEqual(f.Evidence[0].Signals, []detect.Signal{{Source: detect.Header, Name: "Server"}}) {
						t.Errorf("unexpected independent nginx evidence: %+v", f)
					}
				case "django":
					requireDjangoFinding(t, got[i:i+1])
				case "python":
					requireLanguageInference(t, got[i:i+1], "python", "django")
				}
			}
			if strings.Join(ids, " ") != tc.ids {
				t.Fatalf("findings=%+v want IDs=%s", got, tc.ids)
			}
		})
	}
}
