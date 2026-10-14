package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const reactClientAssignment = `e.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE=n;`
const reactElementSymbol = `Symbol.for("react.transitional.element")`

func TestReactClientRuntime(t *testing.T) {
	engine := bundledEngine(t)
	cases := map[string]string{
		"compact":       reactClientAssignment + reactElementSymbol,
		"spacing":       "exports \n. __CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE = shared ;\nSymbol . for ( 'react.transitional.element' )",
		"inline-object": strings.Replace(reactClientAssignment, "=n;", "={H:null};", 1) + reactElementSymbol,
		"nested-export": "module." + reactClientAssignment + reactElementSymbol,
		"reversed":      reactElementSymbol + ";" + reactClientAssignment,
		// The engine does not parse JS or establish execution. Copied marker
		// pairs can match; this must remain inferred.
		"commented": "/* " + reactClientAssignment + reactElementSymbol + " */",
	}
	for _, name := range []string{"react-19-client.js", "react-19-client.min.js"} {
		cases[name] = string(htmlFixture(t, name))
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			url := "https://example.test/renamed?private-token=1"
			got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, body)}})
			if len(got) != 1 || got[0].ID != "react" || got[0].Name != "React" || got[0].Category != detect.JSFramework || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
				t.Fatalf("findings=%+v", got)
			}
			e := got[0].Evidence[0]
			if e.RuleID != "asset-client-runtime" || e.AssetURL != url || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}) {
				t.Fatalf("evidence=%+v", e)
			}
			if strings.Contains(e.Description, "private-") || strings.Contains(e.Description, "__CLIENT_INTERNALS") {
				t.Errorf("raw data in description: %q", e.Description)
			}
		})
	}
}

func TestReactClientRuntimeNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	valid := reactClientAssignment + reactElementSymbol
	cases := map[string]string{
		"empty":               "",
		"symbol-only":         reactElementSymbol,
		"internals-only":      reactClientAssignment,
		"bare-names":          `__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE react.transitional.element`,
		"generic-hooks":       `React.useState();React.createElement("div");document.getElementById("root");`,
		"read-not-assignment": `var x=e.__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE;` + reactElementSymbol,
		"comparison":          strings.Replace(valid, "=n;", "===n;", 1),
		"compound-assignment": strings.Replace(valid, "=n;", "+=n;", 1),
		"no-assigned-value":   strings.Replace(valid, "=n;", "=;", 1),
		"property-suffix":     strings.Replace(valid, "CANNOT_UPGRADE", "CANNOT_UPGRADE_EXTRA", 1),
		"property-prefix":     strings.Replace(valid, ".__CLIENT", ".custom__CLIENT", 1),
		"wrong-case":          strings.Replace(valid, "__CLIENT", "__client", 1),
		"bracket-property":    `e["__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE"]=n;` + reactElementSymbol,
		"symbol-prefix":       strings.Replace(valid, "Symbol.for", "OtherSymbol.for", 1),
		"symbol-member":       strings.Replace(valid, "Symbol.for", "other.Symbol.for", 1),
		"function-suffix":     strings.Replace(valid, "Symbol.for", "Symbol.format", 1),
		"symbol-suffix":       strings.Replace(valid, "react.transitional.element", "react.transitional.element.extra", 1),
		"legacy-symbol":       strings.Replace(valid, "react.transitional.element", "react.element", 1),
		"legacy-internals":    strings.Replace(valid, "__CLIENT_INTERNALS_DO_NOT_USE_OR_WARN_USERS_THEY_CANNOT_UPGRADE", "__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED", 1),
		// Authored React 18 / Preact-compat-like decoy. Old API/version
		// markers are intentionally not an alternative React rule.
		"legacy-compat": `e.version="18.3.1";e.__SECRET_INTERNALS_DO_NOT_USE_OR_YOU_WILL_BE_FIRED=n;Symbol.for("react.element");`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestReactClientRuntimeIsolation(t *testing.T) {
	engine := bundledEngine(t)
	valid := reactClientAssignment + reactElementSymbol
	for name, input := range map[string]detect.Input{
		"inline-html":      {HTML: []byte("<script>" + valid + "</script>")},
		"headers-cookies":  {Headers: http.Header{"X-Marker": {valid}}, CookieNames: []string{valid}},
		"css":              {Assets: []detect.Asset{cssAsset("https://example.test/file", valid)}},
		"empty-url":        {Assets: []detect.Asset{scriptAsset("", valid)}},
		"split-files":      {Assets: []detect.Asset{scriptAsset("https://example.test/one", reactClientAssignment), scriptAsset("https://example.test/two", reactElementSymbol)}},
		"split-kinds":      {Assets: []detect.Asset{scriptAsset("https://example.test/one", reactClientAssignment), cssAsset("https://example.test/two", reactElementSymbol)}},
		"split-page-asset": {HTML: []byte(reactClientAssignment), Assets: []detect.Asset{scriptAsset("https://example.test/file", reactElementSymbol)}},
		"filename-only":    {Assets: []detect.Asset{scriptAsset("https://example.test/react-19.js", "generic")}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(input); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
	// Next.js does not imply React, and neither framework implies a language.
	input := detect.Input{Headers: http.Header{"X-Powered-By": {"Next.js"}}}
	if got := engine.Detect(input); len(got) != 1 || got[0].ID != "nextjs" {
		t.Fatalf("header-only findings=%+v", got)
	}
	one, two := "https://example.test/one", "https://example.test/two"
	input.Assets = []detect.Asset{scriptAsset(one, valid+";"+valid), scriptAsset(two, valid), scriptAsset(one, valid)}
	got := engine.Detect(input)
	if len(got) != 2 || got[0].ID != "nextjs" || got[0].State != detect.Detected || got[1].ID != "react" || got[1].State != detect.Inferred || len(got[1].Evidence) != 2 || got[1].Evidence[0].AssetURL != one || got[1].Evidence[1].AssetURL != two {
		t.Fatalf("mixed findings=%+v", got)
	}
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Error("unstable evidence")
	}
	got[1].Evidence[0].AssetURL = "changed"
	if again := engine.Detect(input); again[1].Evidence[0].AssetURL != one {
		t.Error("shared evidence across scans")
	}
	if got := engine.Detect(detect.Input{}); len(got) != 0 {
		t.Fatal("retained asset evidence across scans")
	}
}
