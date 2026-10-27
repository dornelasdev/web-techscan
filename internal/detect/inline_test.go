package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"webscan/internal/detect"
)

func TestInlineCSSFingerprintBaselines(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct {
		file, id, rule string
		signals        int
	}{
		{"bootstrap-5.2.css", "bootstrap", "inline-css-banner-and-buttons", 2},
		{"bootstrap-5.3.min.css", "bootstrap", "inline-css-banner-and-buttons", 2},
		{"tailwind-3.4.css", "tailwindcss", "inline-css-v3-banner-and-preflight", 2},
		{"tailwind-4.1.min.css", "tailwindcss", "inline-css-v4-banner-and-translate", 3},
	} {
		t.Run(tc.file, func(t *testing.T) {
			got := engine.Detect(detect.Input{InlineStyles: []detect.InlineStyle{{Index: 7, Body: htmlFixture(t, tc.file)}}})
			if len(got) != 1 || got[0].ID != tc.id || got[0].Category != detect.UIFramework || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
				t.Fatalf("findings=%+v", got)
			}
			e := got[0].Evidence[0]
			if e.RuleID != tc.rule || e.StyleBlock != 7 || e.AssetURL != "" || e.InferredFrom != "" || len(e.Signals) != tc.signals {
				t.Fatalf("inline provenance=%+v", e)
			}
			for _, signal := range e.Signals {
				if signal.Source != detect.InlineCSS || signal.Name != "" {
					t.Fatalf("signal=%+v", signal)
				}
			}
		})
	}
}

func TestInlineCSSRequiresOneBlockAndSeparateSource(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct{ name, prefix, rest string }{
		{"bootstrap", bootstrapBanner, bootstrapButtons},
		{"tailwind3", tailwind3Banner, tailwind3Preflight},
		{"tailwind4", tailwind4Banner + tailwind4Property, tailwind4Translate},
	} {
		full := tc.prefix + tc.rest
		for name, input := range map[string]detect.Input{
			"split-blocks":              {InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(tc.prefix)}, {Index: 2, Body: []byte(tc.rest)}}},
			"split-page":                {HTML: []byte(tc.prefix), InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(tc.rest)}}},
			"split-asset":               {Assets: []detect.Asset{cssAsset("https://example.test/a.css", tc.prefix)}, InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(tc.rest)}}},
			"reverse-split-asset":       {Assets: []detect.Asset{cssAsset("https://example.test/a.css", tc.rest)}, InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(tc.prefix)}}},
			"html-only":                 {HTML: []byte("<style>" + full + "</style>")},
			"headers-and-cookies":       {Headers: http.Header{"X-Marker": {full}}, CookieNames: []string{full}},
			"javascript":                {Assets: []detect.Asset{scriptAsset("https://example.test/a.js", full)}},
			"inline-disguised-as-asset": {Assets: []detect.Asset{{URL: "https://example.test/", Source: detect.InlineCSS, Body: []byte(full)}}},
			"invalid-index":             {InlineStyles: []detect.InlineStyle{{Index: 0, Body: []byte(full)}, {Index: -1, Body: []byte(full)}}},
			"prefix-only":               {InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(tc.prefix)}}},
			"rest-only":                 {InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(tc.rest)}}},
		} {
			t.Run(tc.name+"/"+name, func(t *testing.T) {
				if got := engine.Detect(input); len(got) != 0 {
					t.Fatalf("cross-source/block finding=%+v", got)
				}
			})
		}
	}
	if got := engine.Detect(detect.Input{InlineStyles: []detect.InlineStyle{{Index: 1, Body: htmlFixture(t, "react-19-client.min.js")}}}); len(got) != 0 {
		t.Fatalf("inline CSS supplied JS evidence: %+v", got)
	}
}

func TestInlineAndAssetCSSEvidenceOrderingAndCopies(t *testing.T) {
	engine := bundledEngine(t)
	b := bootstrapBanner + bootstrapButtons
	tw3 := tailwind3Banner + tailwind3Preflight
	tw4 := tailwind4Banner + tailwind4Property + tailwind4Translate
	input := detect.Input{
		Assets:       []detect.Asset{cssAsset("https://example.test/shared.css?private-query", b+tw3)},
		InlineStyles: []detect.InlineStyle{{Index: 4, Body: []byte(b + tw3)}, {Index: 2, Body: []byte(tw4)}, {Index: 8, Body: []byte(tw3)}, {Index: 4, Body: []byte(b + tw3)}},
	}
	got := engine.Detect(input)
	if len(got) != 2 || got[0].ID != "bootstrap" || got[1].ID != "tailwindcss" {
		t.Fatalf("findings=%+v", got)
	}
	for i, want := range [][]struct {
		rule  string
		block int
	}{
		{{"asset-css-banner-and-buttons", 0}, {"inline-css-banner-and-buttons", 4}},
		{{"asset-css-v3-banner-and-preflight", 0}, {"inline-css-v3-banner-and-preflight", 4}, {"inline-css-v3-banner-and-preflight", 8}, {"inline-css-v4-banner-and-translate", 2}},
	} {
		if got[i].State != detect.Inferred || len(got[i].Evidence) != len(want) {
			t.Fatalf("finding=%+v", got[i])
		}
		for j, expected := range want {
			e := got[i].Evidence[j]
			url, source := "", detect.InlineCSS
			if expected.block == 0 {
				url, source = input.Assets[0].URL, detect.AssetCSS
			}
			if e.RuleID != expected.rule || e.StyleBlock != expected.block || e.AssetURL != url {
				t.Fatalf("ordering/provenance=%+v", e)
			}
			for _, signal := range e.Signals {
				if signal.Source != source {
					t.Fatalf("source=%+v", signal)
				}
			}
		}
	}
	again := engine.Detect(input)
	if !reflect.DeepEqual(again, got) {
		t.Fatal("inline scans are unstable")
	}
	got[0].Evidence[1].StyleBlock = 99
	got[0].Evidence[1].Signals[0].Source = detect.HTML
	if next := engine.Detect(input); !reflect.DeepEqual(next, again) {
		t.Fatal("inline evidence leaked across scans")
	}
}

func TestInlineCSSRuleValidation(t *testing.T) {
	const marker = `{"source":"inline_css","pattern":"FIRST"}`
	rule := func(matchers string) string {
		return `{"id":"inline","state":"inferred","description":"Synthetic inline markers","all":[` + matchers + `]}`
	}
	good := document(technology("example", rule(marker+`,{"source":"inline_css","pattern":"SECOND"}`), ""))
	engine, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(good)}})
	if err != nil {
		t.Fatal(err)
	}
	if got := engine.Detect(detect.Input{InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte("FIRST SECOND")}}}); len(got) != 1 || got[0].Evidence[0].StyleBlock != 1 {
		t.Fatalf("valid inline rule=%+v", got)
	}
	for _, other := range []string{`{"source":"html","pattern":"SECOND"}`, `{"source":"header","name":"Server","pattern":"SECOND"}`, `{"source":"cookie","pattern":"SECOND"}`, `{"source":"asset_css","pattern":"SECOND"}`, `{"source":"asset_javascript","pattern":"SECOND"}`} {
		for _, matchers := range []string{marker + "," + other, other + "," + marker} {
			bad := document(technology("example", rule(matchers), ""))
			if _, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(bad)}}); err == nil || !strings.Contains(err.Error(), "inline CSS rules") {
				t.Fatalf("mixed source accepted: %s err=%v", matchers, err)
			}
		}
	}
	for _, bad := range []string{
		strings.Replace(good, `"source":"inline_css"`, `"source":"inline_css","name":"invalid"`, 1),
		strings.Replace(good, `"all":`, `"http_status":{"min":400,"max":599},"all":`, 1),
	} {
		if _, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(bad)}}); err == nil {
			t.Fatalf("invalid inline rule accepted: %s", bad)
		}
	}
}
