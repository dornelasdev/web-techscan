package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"testing"

	"webscan/internal/detect"
)

func requireCaddy(t *testing.T, got []detect.Finding, state detect.State, rules ...string) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "caddy" || got[0].Name != "Caddy" || got[0].Category != detect.WebServer || got[0].State != state || len(got[0].Evidence) != len(rules) {
		t.Fatalf("want only %s Caddy with rules %v, got %+v", state, rules, got)
	}
	for i, rule := range rules {
		name := "Server"
		if rule == "via-header" {
			name = "Via"
		}
		e := got[0].Evidence[i]
		if e.RuleID != rule || e.Description == "" || e.InferredFrom != "" || e.AssetURL != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.Header, Name: name}}) {
			t.Errorf("unexpected Caddy evidence: %+v", e)
		}
	}
}

func TestCaddyHeaderBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct {
		header, rule       string
		state              detect.State
		positive, negative []string
	}{
		{"Server", "server-header", detect.Detected,
			[]string{"Caddy", "caddy", "CADDY", "\t cAdDy \t"},
			[]string{"", "Cad", "dy", "Cad dy", "Cad\tdy", "Caddy/2.11.7", "Caddy v2.11.7", "Caddy2",
				"Caddy-compatible", "NotCaddy", "CaddyHTTP", "CaddyCaddy", "Caddy (Unix)", "Caddy proxy", "proxy Caddy",
				"Caddy, nginx", "nginx, Caddy", "Caddy\n", "Caddy\r\n", "Caddy\x00", "Caddy\x7f",
				"\vCaddy", "\fCaddy", "\u00a0Caddy", "Caddy\u00a0", "Ｃaddy", "Cаddy", "1.1 Caddy"}},
		{"Via", "via-header", detect.Inferred,
			[]string{"1.0 Caddy", "1.1 Caddy", "2.0 Caddy", "3.0 Caddy", "\t 1.1\t cAdDy \t"},
			[]string{"", "Caddy", "1 Caddy", "2 Caddy", "HTTP/1.1 Caddy", "1.2 Caddy", "2.1 Caddy", "4.0 Caddy",
				"01.1 Caddy", "1.01 Caddy", "1..1 Caddy", "1.1Caddy", "1.1 Cad dy", "1.1 Caddy/2.11.7",
				"1.1 Caddy:80", "1.1 caddy.example", "1.1 NotCaddy", "1.1 Caddy-compatible", "1.1 Caddy proxy",
				"1.1 other (Caddy)", "1.1 Caddy (proxy)", "1.1 Caddy, 1.1 other", "1.1 other, 1.1 Caddy",
				", 1.1 Caddy", "1.1 Caddy,", "1.1 Caddy\n", "1.1\r\n Caddy", "1.1 Caddy\x00", "1.1 Caddy\x7f",
				"1.1\u00a0Caddy", "1.1 Caddy\u00a0", "１.１ Caddy", "1.1 Ｃaddy", "1.1 Cаddy"}},
	} {
		for _, value := range tc.positive {
			t.Run(tc.header+"/positive/"+value, func(t *testing.T) {
				headers := make(http.Header)
				headers.Add(tc.header, "unrelated")
				headers.Add(tc.header, value)
				headers.Add(tc.header, value)
				requireCaddy(t, engine.Detect(detect.Input{Headers: headers}), tc.state, tc.rule)
			})
		}
		for _, value := range tc.negative {
			t.Run(tc.header+"/negative/"+value, func(t *testing.T) {
				if got := engine.Detect(detect.Input{Headers: http.Header{tc.header: {value}}}); len(got) != 0 {
					t.Fatalf("unexpected findings: %+v", got)
				}
			})
		}
	}
}

func TestCaddyRuleCombinations(t *testing.T) {
	engine := bundledEngine(t)
	for mask := 0; mask < 4; mask++ {
		for _, status := range []int{0, 200, 403, 500} {
			t.Run(fmt.Sprintf("rules=%02b/status=%d", mask, status), func(t *testing.T) {
				input := detect.Input{HTTPStatus: status, Headers: make(http.Header)}
				rules := []string{}
				state := detect.Inferred
				if mask&1 != 0 {
					input.Headers["server"] = []string{"Caddy", "Caddy"}
					rules = append(rules, "server-header")
					state = detect.Detected
				}
				if mask&2 != 0 {
					input.Headers["VIA"] = []string{"1.1 Caddy", "2.0 Caddy", "1.1 Caddy"}
					rules = append(rules, "via-header")
				}
				got := engine.Detect(input)
				if mask == 0 {
					if len(got) != 0 {
						t.Fatalf("unexpected findings: %+v", got)
					}
					return
				}
				requireCaddy(t, got, state, rules...)
				if fresh := engine.Detect(input); !reflect.DeepEqual(fresh, got) {
					t.Error("repeated scan changed findings")
				}
				got[0].Evidence[0].Description, got[0].Evidence[0].Signals[0].Name = "caller mutation", "changed"
				requireCaddy(t, engine.Detect(input), state, rules...)
				if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
					t.Errorf("findings retained across scans: %+v", empty)
				}
			})
		}
	}
}

func TestCaddySourceAndBackendIsolation(t *testing.T) {
	engine := bundledEngine(t)
	for _, input := range []detect.Input{
		{Headers: http.Header{"X-Server": {"Caddy"}, "X-Powered-By": {"Caddy"}, "X-Via": {"1.1 Caddy"}}},
		{Headers: http.Header{"Server": {"1.1 Caddy"}, "Via": {"Caddy"}}},
		{Headers: http.Header{"Server": {"Cad", "dy"}, "Via": {"1.1", "Caddy"}}},
		{HTML: []byte("<p>Caddy 1.1 Caddy Go Golang</p>"), CookieNames: []string{"Caddy", "1.1 Caddy"}},
		{Assets: []detect.Asset{
			{URL: "https://example.test/app.js", Source: detect.AssetJavaScript, Body: []byte("Caddy 1.1 Caddy")},
			{URL: "https://example.test/app.css", Source: detect.AssetCSS, Body: []byte("Caddy 1.1 Caddy")},
		}},
	} {
		if got := engine.Detect(input); len(got) != 0 {
			t.Errorf("wrong-source or split values produced findings: %+v", got)
		}
	}
	for _, server := range []bool{false, true} {
		for mask := 0; mask < 4; mask++ {
			t.Run(fmt.Sprintf("server=%t/django=%02b", server, mask), func(t *testing.T) {
				input := detect.Input{Headers: http.Header{"Via": {"1.1 Caddy"}, "Server": {"nginx"}, "X-Powered-By": {"Express"}}}
				state, rules := detect.Inferred, []string{"via-header"}
				if server {
					input.Headers.Add("Server", "Caddy")
					state, rules = detect.Detected, []string{"server-header", "via-header"}
				}
				if mask&1 != 0 {
					input.CookieNames = []string{"csrftoken"}
				}
				if mask&2 != 0 {
					input.HTML = []byte(djangoInput)
				}
				wantIDs := []string{"caddy", "express", "nginx"}
				if mask == 3 {
					wantIDs = append(wantIDs, "django", "python")
				}
				sort.Strings(wantIDs)
				got := engine.Detect(input)
				ids := []string{}
				for i, f := range got {
					ids = append(ids, f.ID)
					switch f.ID {
					case "caddy":
						requireCaddy(t, got[i:i+1], state, rules...)
					case "django":
						requireDjangoFinding(t, got[i:i+1])
					case "python":
						requireLanguageInference(t, got[i:i+1], "python", "django")
					}
				}
				if !reflect.DeepEqual(ids, wantIDs) {
					t.Fatalf("findings=%+v want=%v without language/topology guesses", got, wantIDs)
				}
			})
		}
	}
}
