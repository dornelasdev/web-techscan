package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func requireLiteSpeed(t *testing.T, got []detect.Finding) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "litespeed" || got[0].Name != "LiteSpeed" || got[0].Category != detect.WebServer || got[0].State != detect.Detected || len(got[0].Evidence) != 1 {
		t.Fatalf("want only detected LiteSpeed family, got %+v", got)
	}
	e := got[0].Evidence[0]
	if e.RuleID != "server-header" || e.Description != "Server header reports the LiteSpeed family without establishing an edition; this may be an intermediary" || e.InferredFrom != "" || e.AssetURL != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.Header, Name: "Server"}}) {
		t.Errorf("unexpected LiteSpeed evidence: %+v", e)
	}
}

func TestLiteSpeedStatusAndReuse(t *testing.T) {
	engine := bundledEngine(t)
	for _, banner := range []string{"LiteSpeed", "LiteSpeed/1.8.4 Open", "LiteSpeed/1.9.3 Open"} {
		for _, status := range []int{0, 200, 403, 500} {
			t.Run(fmt.Sprintf("%s/status=%d", banner, status), func(t *testing.T) {
				input := detect.Input{HTTPStatus: status, Headers: http.Header{"server": {banner, banner}, "SERVER": {banner}}}
				got := engine.Detect(input)
				requireLiteSpeed(t, got)
				if fresh := engine.Detect(input); !reflect.DeepEqual(fresh, got) {
					t.Error("repeated scan changed findings")
				}
				got[0].Evidence[0].Description, got[0].Evidence[0].Signals[0].Name = "caller mutation", "changed"
				requireLiteSpeed(t, engine.Detect(input))
				if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
					t.Errorf("findings leaked across scans: %+v", empty)
				}
			})
		}
	}
}

func TestLiteSpeedSourceIsolationAndIndependentPHP(t *testing.T) {
	engine := bundledEngine(t)
	for _, banner := range []string{"LiteSpeed", "LiteSpeed/1.9.3 Open"} {
		for _, input := range []detect.Input{
			{Headers: http.Header{"X-Turbo-Charged-By": {banner}, "X-Powered-By": {banner}, "X-Server": {banner}, "Via": {banner}}},
			{Headers: http.Header{"X-LiteSpeed-Cache": {"hit"}, "X-LiteSpeed-Cache-Control": {"public,max-age=3600"}}},
			{Headers: http.Header{"Server": {"Lite", "Speed", "LiteSpeed/", "1.9.3 Open", "LiteSpeed/1.9.3", "Open"}}},
			{HTTPStatus: 403, CookieNames: []string{"litespeed", "lscache"}, HTML: []byte("<h1>Powered By LiteSpeed</h1>" + banner)},
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
		name, ids string
		cookies   []string
		directPHP bool
	}{
		{"server-only", "litespeed", nil, false},
		{"partial-laravel", "litespeed", []string{"laravel_session"}, false},
		{"laravel-inference", "laravel litespeed php", []string{"laravel_session", "XSRF-TOKEN"}, false},
		{"independent-php-header", "litespeed php", nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := detect.Input{Headers: http.Header{"Server": {"LiteSpeed/1.9.3 Open"}}, CookieNames: tc.cookies}
			if tc.directPHP {
				input.Headers.Set("X-Powered-By", "PHP/8.3.12")
			}
			got, ids := engine.Detect(input), []string{}
			for i, f := range got {
				ids = append(ids, f.ID)
				if f.ID == "litespeed" {
					requireLiteSpeed(t, got[i:i+1])
				}
				if f.ID == "php" {
					if !tc.directPHP {
						requireLanguageInference(t, got[i:i+1], "php", "laravel")
					} else if f.State != detect.Detected || len(f.Evidence) != 1 || f.Evidence[0].InferredFrom != "" || f.Evidence[0].RuleID != "powered-by-header" {
						t.Errorf("unexpected independent PHP evidence: %+v", f)
					}
				}
			}
			if !reflect.DeepEqual(ids, strings.Fields(tc.ids)) {
				t.Fatalf("findings=%+v want IDs=%s", got, tc.ids)
			}
		})
	}
}
