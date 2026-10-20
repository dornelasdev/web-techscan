package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"testing"

	"webscan/internal/detect"
)

func requireFiber(t *testing.T, got []detect.Finding) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "fiber" || got[0].Name != "Fiber" || got[0].Category != detect.Framework || got[0].State != detect.Detected || len(got[0].Evidence) != 1 {
		t.Fatalf("want only detected Fiber framework, got %+v", got)
	}
	e := got[0].Evidence[0]
	if e.RuleID != "server-header" || e.Description != "Server header reports Fiber; this may be an intermediary" || e.InferredFrom != "" || e.AssetURL != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.Header, Name: "Server"}}) {
		t.Errorf("unexpected Fiber evidence: %+v", e)
	}
}

func TestFiberHeaderBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for _, value := range []string{"Fiber", "fiber", "FIBER", "\t fIbEr \t"} {
		for _, status := range []int{0, 200, 403, 500} {
			t.Run(fmt.Sprintf("%s/status=%d", value, status), func(t *testing.T) {
				input := detect.Input{HTTPStatus: status, Headers: http.Header{"server": {"unrelated", value}, "SERVER": {value}}}
				got := engine.Detect(input)
				requireFiber(t, got)
				if fresh := engine.Detect(input); !reflect.DeepEqual(fresh, got) {
					t.Error("repeated scan changed findings")
				}
				got[0].Evidence[0].Description, got[0].Evidence[0].Signals[0].Name = "caller mutation", "changed"
				requireFiber(t, engine.Detect(input))
				if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
					t.Errorf("findings retained across scans: %+v", empty)
				}
			})
		}
	}
	for _, value := range []string{
		"", "Fib", "er", "Fib er", "Fib\ter", "Fiber/2.52.9", "Fiber/3.0.0", "Fiber v3", "Fiber3",
		"Fiber-compatible", "NotFiber", "FiberHTTP", "FiberFiber", "Fiber (Go)", "Fiber proxy", "proxy Fiber",
		"Fiber, nginx", "nginx, Fiber", "Fiber\n", "Fiber\r\n", "Fiber\x00", "Fiber\x7f", "\vFiber", "\fFiber",
		"\u00a0Fiber", "Fiber\u00a0", "Ｆiber", "Fıber", "Fİber", "Fіber", "fasthttp", "Go", "Golang",
	} {
		t.Run("negative/"+value, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Headers: http.Header{"Server": {value}}}); len(got) != 0 {
				t.Fatalf("unexpected findings: %+v", got)
			}
		})
	}
}

func TestFiberSourceIsolation(t *testing.T) {
	engine := bundledEngine(t)
	for _, input := range []detect.Input{
		{Headers: http.Header{"Via": {"Fiber", "1.1 Fiber"}, "X-Powered-By": {"Fiber"}, "X-Server": {"Fiber"}}},
		{Headers: http.Header{"Server": {"Fib", "er"}}},
		{HTML: []byte("<p>Fiber Go Golang fasthttp</p>"), CookieNames: []string{"Fiber", "fiber_session"}},
		{HTTPStatus: 404, HTML: []byte("Cannot GET /")},
		{HTTPStatus: 404, HTML: []byte("404 page not found")},
		{HTTPStatus: 404, HTML: []byte(`{"message":"Not Found"}`)},
		{Assets: []detect.Asset{
			{URL: "https://example.test/app.js", Source: detect.AssetJavaScript, Body: []byte("Fiber Go fasthttp")},
			{URL: "https://example.test/app.css", Source: detect.AssetCSS, Body: []byte("Fiber Go fasthttp")},
		}},
	} {
		if got := engine.Detect(input); len(got) != 0 {
			t.Errorf("wrong-source/generic evidence produced findings: %+v", got)
		}
	}
}

func TestFiberIndependentBackendEvidence(t *testing.T) {
	engine := bundledEngine(t)
	for _, fiber := range []bool{false, true} {
		for mask := 0; mask < 4; mask++ {
			t.Run(fmt.Sprintf("fiber=%t/django=%02b", fiber, mask), func(t *testing.T) {
				input := detect.Input{Headers: http.Header{"Server": {"nginx"}, "Via": {"1.1 Caddy"}, "X-Powered-By": {"Express"}}}
				wantIDs := []string{"caddy", "express", "nginx"}
				if fiber {
					input.Headers.Add("Server", "Fiber")
					wantIDs = append(wantIDs, "fiber")
				}
				if mask&1 != 0 {
					input.CookieNames = []string{"csrftoken"}
				}
				if mask&2 != 0 {
					input.HTML = []byte(djangoInput)
				}
				if mask == 3 {
					wantIDs = append(wantIDs, "django", "python")
				}
				sort.Strings(wantIDs)
				got, ids := engine.Detect(input), []string{}
				for i, f := range got {
					ids = append(ids, f.ID)
					switch f.ID {
					case "fiber":
						requireFiber(t, got[i:i+1])
					case "caddy":
						requireCaddy(t, got[i:i+1], detect.Inferred, "via-header")
					case "django":
						requireDjangoFinding(t, got[i:i+1])
					case "python":
						requireLanguageInference(t, got[i:i+1], "python", "django")
					}
				}
				if !reflect.DeepEqual(ids, wantIDs) {
					t.Fatalf("findings=%+v want=%v; no Go/server/runtime implications", got, wantIDs)
				}
			})
		}
	}
}
