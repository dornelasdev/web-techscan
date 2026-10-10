package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

var reactDOMMarkers = []string{
	`var fiber="__reactFiber$"+suffix;`,
	`var props="__reactProps$"+suffix;`,
	`var container="__reactContainer$"+suffix;`,
	`var url="https://reactjs.org/docs/error-decoder.html?invariant="+code;`,
	`var message="Minified React error #"+code+"; visit "+url;`,
}

func TestReactDOMRuntime(t *testing.T) {
	engine := bundledEngine(t)
	body := strings.Join(reactDOMMarkers, "\n")
	cases := map[string]string{
		"compact":       body,
		"single-quotes": strings.ReplaceAll(body, `"`, `'`),
		"spacing":       strings.NewReplacer("var ", "var\n ", "+suffix", "\n+ suffix", "+code", "\n+ code").Replace(body),
		"reversed":      strings.Join([]string{reactDOMMarkers[4], reactDOMMarkers[3], reactDOMMarkers[2], reactDOMMarkers[1], reactDOMMarkers[0]}, "\n"),
		// Raw-text matching cannot establish execution or distinguish copied code.
		"commented":          "/* ;" + body + " */",
		"let-const":          strings.NewReplacer("var fiber", "let fiber", "var props", "const props").Replace(body),
		"bare-assignments":   strings.ReplaceAll(body, "var ", ""),
		"comma-declarations": strings.ReplaceAll(body, ";\nvar ", ","),
	}
	for _, name := range []string{"react-dom-18.js", "react-dom-18.min.js"} {
		cases[name] = string(htmlFixture(t, name))
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			url := "https://example.test/renamed?private-token=1"
			got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, body)}})
			assertReactDOMEvidence(t, got, []string{url})
			if strings.Contains(got[0].Evidence[0].Description, "private-") || strings.Contains(got[0].Evidence[0].Description, "__reactFiber") {
				t.Error("raw capture data in description")
			}
		})
	}
}

func TestReactDOMRuntimeMarkerSubsets(t *testing.T) {
	engine := bundledEngine(t)
	for mask := 0; mask < 1<<len(reactDOMMarkers); mask++ {
		t.Run(fmt.Sprintf("%05b", mask), func(t *testing.T) {
			var body []string
			for i, marker := range reactDOMMarkers {
				if mask&(1<<i) != 0 {
					body = append(body, marker)
				}
			}
			url := "https://example.test/file"
			got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, strings.Join(body, "\n"))}})
			if mask == (1<<len(reactDOMMarkers))-1 {
				assertReactDOMEvidence(t, got, []string{url})
			} else if len(got) != 0 {
				t.Fatalf("partial markers produced findings=%+v", got)
			}
		})
	}
}

func TestReactDOMRuntimeNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	valid := strings.Join(reactDOMMarkers, "\n")
	cases := map[string]string{
		"bare-markers": `__reactFiber$ __reactProps$ __reactContainer$ https://reactjs.org/docs/error-decoder.html?invariant= Minified React error #`,
		// Authored Preact-compat-like scaffold; not a bundled upstream runtime.
		"legacy-compat":        `e.version="18.3.1";e.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED=n;Symbol.for("react.element");`,
		"generic-react-dom":    `ReactDOM.createRoot(root).render(React.createElement("div"));`,
		"url-literal-only":     strings.Replace(valid, `"+code;`, `";`, 1),
		"url-spoof-host":       strings.Replace(valid, "reactjs.org/", "reactjs.org.example/", 1),
		"url-suffix":           strings.Replace(valid, "invariant=", "invariant=extra", 1),
		"modern-error-url":     strings.Replace(valid, "https://reactjs.org/docs/error-decoder.html?invariant=", "https://react.dev/errors/", 1),
		"url-call-value":       strings.Replace(valid, `"+code;`, `"+code();`, 1),
		"message-literal-only": strings.Replace(valid, `"Minified React error #"+code+"; visit "`, `"Minified React error #"`, 1),
		"message-prefix":       strings.Replace(valid, "Minified React error #", "Other Minified React error #", 1),
		"message-suffix":       strings.Replace(valid, "Minified React error #", "Minified React error #extra", 1),
		"wrong-visit":          strings.Replace(valid, "; visit ", "; read ", 1),
		"message-call-value":   strings.Replace(valid, `"+code+"; visit "`, `"+code()+"; visit "`, 1),
		"wrong-case":           strings.ReplaceAll(valid, "React", "react"),
	}
	for i, key := range []string{"fiber", "props", "container"} {
		marker := reactDOMMarkers[i]
		for name, replacement := range map[string]string{
			"read":                 strings.Replace(marker, key+"=", key+";", 1),
			"comparison":           strings.Replace(marker, "=", "===", 1),
			"compound-assignment":  strings.Replace(marker, "=", "+=", 1),
			"qualified-lhs":        strings.Replace(marker, "var "+key, "obj."+key, 1),
			"spaced-qualified-lhs": strings.Replace(marker, "var "+key, "obj . "+key, 1),
			"no-suffix":            strings.Replace(marker, "+suffix", "", 1),
			"suffix-call":          strings.Replace(marker, "+suffix", "+suffix()", 1),
			"suffix-member":        strings.Replace(marker, "+suffix", "+suffix.value", 1),
			"literal-prefix":       strings.Replace(marker, `"__react`, `"other__react`, 1),
			"literal-suffix":       strings.Replace(marker, `$"`, `$extra"`, 1),
			"literal-no-dollar":    strings.Replace(marker, "$", "", 1),
		} {
			cases[key+"/"+name] = strings.Replace(valid, marker, replacement, 1)
		}
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestReactDOMRuntimeIsolation(t *testing.T) {
	engine := bundledEngine(t)
	valid := strings.Join(reactDOMMarkers, "\n")
	keys, errors := strings.Join(reactDOMMarkers[:3], "\n"), strings.Join(reactDOMMarkers[3:], "\n")
	for name, input := range map[string]detect.Input{
		"inline-html":      {HTML: []byte("<script>" + valid + "</script>")},
		"headers-cookies":  {Headers: http.Header{"X-Marker": {valid}}, CookieNames: []string{valid}},
		"css":              {Assets: []detect.Asset{cssAsset("https://example.test/file", valid)}},
		"empty-url":        {Assets: []detect.Asset{scriptAsset("", valid)}},
		"split-files":      {Assets: []detect.Asset{scriptAsset("https://example.test/keys", keys), scriptAsset("https://example.test/errors", errors)}},
		"split-kinds":      {Assets: []detect.Asset{scriptAsset("https://example.test/keys", keys), cssAsset("https://example.test/errors", errors)}},
		"split-page-asset": {HTML: []byte(keys), Assets: []detect.Asset{scriptAsset("https://example.test/errors", errors)}},
		"filename-only":    {Assets: []detect.Asset{scriptAsset("https://example.test/react-dom-18.js", "generic")}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(input); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
	// Even one omitted marker must not be supplied by another complete capture.
	for i := range reactDOMMarkers {
		parts := append([]string(nil), reactDOMMarkers...)
		parts[i] = ""
		input := detect.Input{Assets: []detect.Asset{
			scriptAsset("https://example.test/one", strings.Join(parts, "\n")),
			scriptAsset("https://example.test/two", reactDOMMarkers[i]),
		}}
		if got := engine.Detect(input); len(got) != 0 {
			t.Fatalf("split marker %d findings=%+v", i, got)
		}
	}
}

func TestReactRuntimeRulesCoexist(t *testing.T) {
	engine := bundledEngine(t)
	dom := strings.Join(reactDOMMarkers, "\n")
	client := reactClientAssignment + reactElementSymbol
	one, two := "https://example.test/z", "https://example.test/a"
	// Duplicate bodies/URLs still yield one evidence item per rule and URL.
	input := detect.Input{Assets: []detect.Asset{scriptAsset(one, dom+";"+client+";"+dom), scriptAsset(two, dom+";"+client), scriptAsset(one, dom+";"+client)}}
	got := engine.Detect(input)
	if len(got) != 1 || got[0].ID != "react" || got[0].State != detect.Inferred || len(got[0].Evidence) != 4 {
		t.Fatalf("findings=%+v", got)
	}
	for i, e := range got[0].Evidence {
		wantRule, count := "asset-client-runtime", 2
		if i >= 2 {
			wantRule, count = "asset-dom-runtime", 5
		}
		wantURL := []string{one, two}[i%2]
		if e.RuleID != wantRule || e.AssetURL != wantURL || len(e.Signals) != count || e.InferredFrom != "" {
			t.Fatalf("evidence=%+v", got[0].Evidence)
		}
	}
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Error("unstable evidence")
	}
	got[0].Evidence[2].AssetURL = "changed"
	if again := engine.Detect(input); again[0].Evidence[2].AssetURL != one {
		t.Error("shared evidence across scans")
	}
	input.Assets[0], input.Assets[1] = input.Assets[1], input.Assets[0]
	reversed := engine.Detect(input)
	if reversed[0].Evidence[0].AssetURL != two || reversed[0].Evidence[2].AssetURL != two {
		t.Error("lost capture order")
	}
	// Separate client/renderer captures support one React finding independently.
	input.Assets = []detect.Asset{scriptAsset(one, client), scriptAsset(two, dom)}
	input.Headers = http.Header{"X-Powered-By": {"Next.js"}}
	separate := engine.Detect(input)
	if len(separate) != 2 || separate[0].ID != "nextjs" || separate[0].State != detect.Detected || separate[1].ID != "react" || separate[1].State != detect.Inferred || len(separate[1].Evidence) != 2 || separate[1].Evidence[0].AssetURL != one || separate[1].Evidence[1].AssetURL != two {
		t.Fatalf("separate findings=%+v", separate)
	}
	if got := engine.Detect(detect.Input{}); len(got) != 0 {
		t.Fatal("retained runtime findings")
	}
}

func assertReactDOMEvidence(t *testing.T, got []detect.Finding, urls []string) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "react" || got[0].Name != "React" || got[0].Category != detect.Framework || got[0].State != detect.Inferred || len(got[0].Evidence) != len(urls) {
		t.Fatalf("findings=%+v", got)
	}
	wantSignals := make([]detect.Signal, 5)
	for i := range wantSignals {
		wantSignals[i].Source = detect.AssetJavaScript
	}
	for i, e := range got[0].Evidence {
		if e.RuleID != "asset-dom-runtime" || e.AssetURL != urls[i] || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, wantSignals) {
			t.Fatalf("evidence=%+v", e)
		}
	}
}
