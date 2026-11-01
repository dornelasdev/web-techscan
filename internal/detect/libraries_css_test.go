package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"webscan/internal/detect"
)

type libraryCSSEvidence struct {
	rule, url string
	source    detect.Source
	block     int
	count     int
}

func libraryCSSExpected(urls map[string]string, css string, block int) map[string][]libraryCSSEvidence {
	return map[string][]libraryCSSEvidence{
		"bootstrap": {{"asset-css-banner-and-buttons", css, detect.AssetCSS, 0, 2}, {"inline-css-banner-and-buttons", "", detect.InlineCSS, block, 2}},
		"jquery":    {{"asset-core-runtime", urls["jquery"], detect.AssetJavaScript, 0, 2}},
		"lazysizes": {{"asset-core-runtime", urls["lazysizes"], detect.AssetJavaScript, 0, 2}},
		"modernizr": {{"asset-v2-core-runtime", urls["modernizr"], detect.AssetJavaScript, 0, 2}},
		"nginx":     {{"server-header", "", detect.Header, 0, 1}},
		"tailwindcss": {{"asset-css-v3-banner-and-preflight", css, detect.AssetCSS, 0, 2},
			{"inline-css-v3-banner-and-preflight", "", detect.InlineCSS, block, 2}},
	}
}

func requireLibraryCSSFindings(t *testing.T, got []detect.Finding, want map[string][]libraryCSSEvidence) {
	t.Helper()
	var ids []string
	for _, id := range []string{"bootstrap", "jquery", "lazysizes", "modernizr", "nginx", "tailwindcss"} {
		if _, ok := want[id]; ok {
			ids = append(ids, id)
		}
	}
	if len(got) != len(want) || len(ids) != len(want) {
		t.Fatalf("findings=%+v want=%v", got, want)
	}
	for i, finding := range got {
		category, state := detect.JSLibrary, detect.Inferred
		if finding.ID == "bootstrap" || finding.ID == "tailwindcss" {
			category = detect.UIFramework
		} else if finding.ID == "nginx" {
			category, state = detect.WebServer, detect.Detected
		}
		if finding.ID != ids[i] || finding.Category != category || finding.State != state || len(finding.Evidence) != len(want[finding.ID]) {
			t.Fatalf("finding=%+v want=%v", finding, want)
		}
		for j, evidence := range finding.Evidence {
			expected := want[finding.ID][j]
			signals := make([]detect.Signal, expected.count)
			for k := range signals {
				signals[k].Source = expected.source
				if expected.source == detect.Header {
					signals[k].Name = "Server"
				}
			}
			if evidence.RuleID != expected.rule || evidence.AssetURL != expected.url || evidence.StyleBlock != expected.block || evidence.InferredFrom != "" || evidence.Description == "" || !reflect.DeepEqual(evidence.Signals, signals) {
				t.Fatalf("evidence=%+v want=%+v", evidence, expected)
			}
		}
	}
}

func TestLibrariesWithDownloadedAndInlineCSS(t *testing.T) {
	engine := bundledEngine(t)
	jquery := jqueryPrototype + jqueryExpando
	lazy := lazysizesConfig + "var core=" + lazysizesAPI + ";"
	modern := modernizrFactory + modernizrPrefixes
	b, tw3 := bootstrapBanner+bootstrapButtons, tailwind3Banner+tailwind3Preflight
	tw4 := tailwind4Banner + tailwind4Property + tailwind4Translate
	for _, separate := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			t.Run(fmt.Sprintf("separate=%t/reverse=%t", separate, reverse), func(t *testing.T) {
				js, css := "https://example.test/shared.js?private-js", "https://example.test/shared.css?private-css"
				urls := map[string]string{"jquery": js, "lazysizes": js, "modernizr": js}
				input := detect.Input{
					Headers:      http.Header{"Server": {"nginx"}},
					Assets:       []detect.Asset{scriptAsset(js, jquery+lazy+modern), cssAsset(css, b+tw3)},
					InlineStyles: []detect.InlineStyle{{Index: 7, Body: []byte(b + tw3)}, {Index: 3, Body: []byte(tw4)}},
				}
				if separate {
					for id := range urls {
						urls[id] = "https://example.test/" + id + "?private-js"
					}
					input.Assets = []detect.Asset{scriptAsset(urls["jquery"], jquery), scriptAsset(urls["lazysizes"], lazy), scriptAsset(urls["modernizr"], modern), cssAsset(css, b+tw3)}
				}
				if reverse {
					for i, j := 0, len(input.Assets)-1; i < j; i, j = i+1, j-1 {
						input.Assets[i], input.Assets[j] = input.Assets[j], input.Assets[i]
					}
				}
				input.Assets = append(input.Assets, input.Assets...)
				input.InlineStyles = append(input.InlineStyles, input.InlineStyles[0])
				want := libraryCSSExpected(urls, css, 7)
				want["tailwindcss"] = append(want["tailwindcss"], libraryCSSEvidence{"inline-css-v4-banner-and-translate", "", detect.InlineCSS, 3, 3})
				got := engine.Detect(input)
				requireLibraryCSSFindings(t, got, want)
				if !reflect.DeepEqual(got, engine.Detect(input)) || len(engine.Detect(detect.Input{})) != 0 {
					t.Fatal("mixed scan changed order or retained findings")
				}
			})
		}
	}
}

func TestPartialLibraryCSSMarkersPreserveOtherFindings(t *testing.T) {
	engine := bundledEngine(t)
	jquery := jqueryPrototype + jqueryExpando
	lazy := lazysizesConfig + "var core=" + lazysizesAPI + ";"
	modern := modernizrFactory + modernizrPrefixes
	allJS := jquery + lazy + modern
	b, tw := bootstrapBanner+bootstrapButtons, tailwind3Banner+tailwind3Preflight
	jsURL, cssURL := "https://example.test/shared.js", "https://example.test/shared.css"
	for _, missing := range []string{"jquery", "lazysizes", "modernizr", "bootstrap", "tailwindcss"} {
		t.Run(missing, func(t *testing.T) {
			js, css, part := allJS, b+tw, ""
			partSource := detect.AssetJavaScript
			switch missing {
			case "jquery":
				js, part = jqueryPrototype+lazy+modern, jqueryExpando
			case "lazysizes":
				js, part = jquery+lazysizesConfig+modern, "var core="+lazysizesAPI+";"
			case "modernizr":
				js, part = jquery+lazy+modernizrFactory, modernizrPrefixes
			case "bootstrap":
				css, part, partSource = bootstrapBanner+tw, bootstrapButtons, detect.AssetCSS
			case "tailwindcss":
				css, part, partSource = b+tailwind3Banner, tailwind3Preflight, detect.AssetCSS
			}
			// Complete wrong-source text and incomplete second captures must
			// not rescue the omitted finding while other technologies match.
			input := detect.Input{
				Headers: http.Header{"Server": {"nginx"}},
				HTML:    []byte("<script>" + allJS + "</script><style>" + b + tw + "</style>"),
				Assets: []detect.Asset{
					scriptAsset(jsURL, js+"/* "+b+tw+" */"),
					cssAsset(cssURL, css+"/* "+allJS+" */"),
					{URL: "https://example.test/part", Source: partSource, Body: []byte(part)},
				},
				InlineStyles: []detect.InlineStyle{{Index: 7, Body: []byte(css + "/* " + allJS + " */")}},
			}
			if partSource == detect.AssetCSS {
				input.InlineStyles = append(input.InlineStyles, detect.InlineStyle{Index: 9, Body: []byte(part)})
			}
			want := libraryCSSExpected(map[string]string{"jquery": jsURL, "lazysizes": jsURL, "modernizr": jsURL}, cssURL, 7)
			delete(want, missing)
			requireLibraryCSSFindings(t, engine.Detect(input), want)
		})
	}
}
