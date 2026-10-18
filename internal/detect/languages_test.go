package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"testing"

	"webscan/internal/detect"
)

func requireLanguageInference(t *testing.T, got []detect.Finding, id, parent string) {
	t.Helper()
	names := map[string]string{"php": "PHP", "python": "Python", "ruby": "Ruby"}
	parents := map[string]string{"laravel": "Laravel", "django": "Django", "rails": "Ruby on Rails"}
	if names[id] == "" || parents[parent] == "" {
		t.Fatalf("unsupported language expectation: %s from %s", id, parent)
	}
	if len(got) != 1 || got[0].ID != id || got[0].Name != names[id] || got[0].Category != detect.Language || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
		t.Fatalf("want one inferred %s finding, got %+v", names[id], got)
	}
	e := got[0].Evidence[0]
	if e.InferredFrom != parent || e.Description != "Inferred from "+parents[parent] || e.RuleID != "" || e.AssetURL != "" || len(e.Signals) != 0 {
		t.Errorf("want only relationship evidence from %s, got %+v", parent, e)
	}
}

func TestLanguageFrameworkSignalCombinations(t *testing.T) {
	engine := bundledEngine(t)
	const (
		djangoCookie = 1 << iota
		djangoField
		railsParameter
		railsCSRF
		laravelSession
		laravelCSRF
	)
	for mask := 0; mask < 1<<6; mask++ {
		for _, directPHP := range []bool{false, true} {
			t.Run(fmt.Sprintf("signals=%06b/direct-PHP=%t", mask, directPHP), func(t *testing.T) {
				input := detect.Input{Headers: http.Header{"Server": {"nginx"}}}
				if directPHP {
					input.Headers.Set("X-Powered-By", "PHP/8.3.12")
				}
				for _, marker := range []struct {
					bit          int
					cookie, html string
				}{
					{djangoCookie, "csrftoken", ""}, {djangoField, "", djangoInput},
					{railsParameter, "", railsParam}, {railsCSRF, "", railsToken},
					{laravelSession, "laravel_session", ""}, {laravelCSRF, "XSRF-TOKEN", ""},
				} {
					if mask&marker.bit != 0 {
						if marker.cookie != "" {
							input.CookieNames = append(input.CookieNames, marker.cookie)
						}
						input.HTML = append(input.HTML, marker.html...)
					}
				}
				wantIDs := []string{"nginx"}
				parents := make(map[string]string)
				for _, pair := range []struct {
					framework, language string
					bits                int
				}{
					{"django", "python", djangoCookie | djangoField},
					{"rails", "ruby", railsParameter | railsCSRF},
					{"laravel", "php", laravelSession | laravelCSRF},
				} {
					if mask&pair.bits == pair.bits {
						wantIDs = append(wantIDs, pair.framework, pair.language)
						parents[pair.language] = pair.framework
					}
				}
				if directPHP && parents["php"] == "" {
					wantIDs = append(wantIDs, "php")
				}
				sort.Strings(wantIDs)
				got := engine.Detect(input)
				ids := make([]string, 0, len(got))
				for _, finding := range got {
					ids = append(ids, finding.ID)
				}
				if !reflect.DeepEqual(ids, wantIDs) {
					t.Fatalf("IDs=%v want=%v; findings=%+v", ids, wantIDs, got)
				}
				for i, finding := range got {
					if finding.Category != detect.Language {
						continue
					}
					if finding.ID != "php" || !directPHP {
						requireLanguageInference(t, got[i:i+1], finding.ID, parents[finding.ID])
						continue
					}
					want := []detect.Evidence{{RuleID: "powered-by-header", Description: "X-Powered-By header reports PHP", Signals: []detect.Signal{{Source: detect.Header, Name: "X-Powered-By"}}}}
					if parents["php"] != "" {
						want = append(want, detect.Evidence{Description: "Inferred from Laravel", InferredFrom: "laravel"})
					}
					if finding.Name != "PHP" || finding.State != detect.Detected || !reflect.DeepEqual(finding.Evidence, want) {
						t.Errorf("direct PHP must retain its state and any Laravel relationship: %+v", finding)
					}
				}
				if fresh := engine.Detect(input); !reflect.DeepEqual(fresh, got) {
					t.Fatal("repeated scans changed findings")
				}
				// Returned findings must not mutate the reusable catalog.
				got[0].Evidence[0].Description = "modified by caller"
				if fresh := engine.Detect(input); fresh[0].Evidence[0].Description == "modified by caller" {
					t.Fatal("caller mutation leaked into another scan")
				}
				if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
					t.Fatalf("findings retained across scans: %+v", empty)
				}
			})
		}
	}
}

func TestLanguagesDoNotUseUnrelatedSources(t *testing.T) {
	engine := bundledEngine(t)
	body := []byte(djangoInput + railsParam + railsToken)
	for _, source := range []detect.Source{detect.AssetJavaScript, detect.AssetCSS} {
		input := detect.Input{
			CookieNames: []string{"csrftoken"},
			Assets:      []detect.Asset{{URL: "https://example.test/app.js", Source: source, Body: body}},
		}
		if got := engine.Detect(input); len(got) != 0 {
			t.Errorf("HTML markers in %s produced findings: %+v", source, got)
		}
	}
	for _, input := range []detect.Input{
		{Headers: http.Header{"Server": {"WSGIServer/0.2 CPython/3.12", "Jetty(12.0.16)"}, "X-Powered-By": {"Python", "Ruby"}}},
		{Headers: http.Header{"X-Example": {string(body)}}, CookieNames: []string{"csrftoken", "JSESSIONID", "PHPSESSID", "_app_session"}},
		{HTML: []byte(`<a href="index.php">Python Ruby Java Node.js</a><script src="app.py"></script><script src="app.rb"></script>`)},
		{Headers: http.Header{"X-Powered-By": {"Express", "Next.js", "Nuxt"}}},
	} {
		for _, finding := range engine.Detect(input) {
			if finding.Category == detect.Language {
				t.Errorf("unrelated evidence must not infer a language: %+v", finding)
			}
		}
	}
}
