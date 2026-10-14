package detect_test

import (
	"fmt"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const angularContextKey = `const key="__ngContext__";`
const angularComponentDefinition = `Component.ɵcmp=runtime.define({type:Component});`
const angularHostVersionArray = `const attrs=["ng-version","20.3.0"];`

func requireAngularRuntime(t *testing.T, got []detect.Finding, url string) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "angular" || got[0].Name != "Angular" || got[0].Category != detect.JSFramework || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
		t.Fatalf("want only inferred Angular, findings=%+v", got)
	}
	e := got[0].Evidence[0]
	if e.RuleID != "asset-component-runtime" || e.AssetURL != url || e.Description == "" || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}) {
		t.Fatalf("runtime evidence=%+v", e)
	}
	for _, raw := range []string{"20.3.0", "__ngContext__", "ɵcmp", "private-"} {
		if strings.Contains(e.Description, raw) {
			t.Errorf("raw value in description: %s", raw)
		}
	}
}

func TestAngularComponentRuntime(t *testing.T) {
	engine := bundledEngine(t)
	valid := angularContextKey + angularComponentDefinition + angularHostVersionArray
	cases := map[string]string{
		"compact":                valid,
		"escaped-property":       strings.Replace(valid, "ɵcmp", `\u0275cmp`, 1),
		"spacing-renamed":        "let $key \n= '__ngContext__' ;\n_this . \\u0275cmp = $runtime . _define ( { type : _this } );\n['ng-version', \"21.2.22\"]",
		"bare-call":              strings.Replace(valid, "runtime.define", "define", 1),
		"qualified-call":         strings.Replace(valid, "runtime.define", "module.runtime.define", 1),
		"comma-declaration":      `var other=1,key='__ngContext__',tail=2;` + angularComponentDefinition + angularHostVersionArray,
		"assignment-only":        `key='__ngContext__';` + angularComponentDefinition + angularHostVersionArray,
		"context-at-end":         angularHostVersionArray + angularComponentDefinition + `key="__ngContext__"`,
		"context-in-function":    `function f(){const key='__ngContext__'}` + angularComponentDefinition + angularHostVersionArray,
		"class-initializer":      angularContextKey + `class C{static x=()=>{this.\u0275cmp=r.d({type:C})}}` + angularHostVersionArray,
		"reversed":               angularHostVersionArray + angularComponentDefinition + angularContextKey,
		"mixed-runtime-versions": valid + `const other=["ng-version","21.0.8"];`,
		// Raw-text matching cannot prove execution, scope, or variable linkage.
		"commented": "/* ;" + valid + " */",
	}
	for _, fixture := range []string{"angular-component.js", "angular-component.min.js"} {
		body, err := os.ReadFile("testdata/coverage/" + fixture)
		if err != nil {
			t.Fatal(err)
		}
		cases[fixture] = string(body)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			url := "https://example.test/renamed?private-token=1"
			requireAngularRuntime(t, engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, body)}}), url)
		})
	}
	for _, version := range []string{"2.0.0", "9.1.0", "100.0.123"} {
		body := strings.Replace(valid, "20.3.0", version, 1)
		requireAngularRuntime(t, engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}), "https://example.test/file")
	}
}

func TestAngularRuntimePartialIndicators(t *testing.T) {
	engine := bundledEngine(t)
	for _, property := range []string{"ɵcmp", `\u0275cmp`} {
		markers := []string{angularContextKey, strings.Replace(angularComponentDefinition, "ɵcmp", property, 1), angularHostVersionArray}
		for mask := 0; mask < 8; mask++ {
			t.Run(fmt.Sprintf("%s/subset-%d", property, mask), func(t *testing.T) {
				var body string
				for i, marker := range markers {
					if mask&(1<<i) != 0 {
						body += marker
					}
				}
				url := "https://example.test/file"
				got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, body)}})
				if mask == 7 {
					requireAngularRuntime(t, got, url)
				} else if len(got) != 0 {
					t.Fatalf("partial indicators produced findings=%+v", got)
				}
			})
		}
	}
}

func TestAngularRuntimeNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	valid := angularContextKey + angularComponentDefinition + angularHostVersionArray
	cases := map[string]string{
		"bare-names":                   `__ngContext__ ɵcmp ng-version Angular`,
		"angularjs":                    `angular.module('app',[]);angular.bootstrap(document,['app']);`,
		"context-read":                 `const key=object.__ngContext__;` + angularComponentDefinition + angularHostVersionArray,
		"context-member":               `object.key="__ngContext__";` + angularComponentDefinition + angularHostVersionArray,
		"context-comparison":           strings.Replace(valid, `key=`, `key===`, 1),
		"context-compound":             strings.Replace(valid, `key=`, `key+=`, 1),
		"context-suffix":               strings.Replace(valid, "__ngContext__", "__ngContext__extra", 1),
		"context-prefix":               strings.Replace(valid, "__ngContext__", "other__ngContext__", 1),
		"context-case":                 strings.Replace(valid, "__ngContext__", "__ngcontext__", 1),
		"context-template":             strings.Replace(valid, `"__ngContext__"`, "`__ngContext__`", 1),
		"context-concatenation":        strings.Replace(valid, `"__ngContext__";`, `"__ngContext__"+suffix;`, 1),
		"component-read":               angularContextKey + `const def=Component.ɵcmp;` + angularHostVersionArray,
		"component-comparison":         strings.Replace(valid, "ɵcmp=", "ɵcmp===", 1),
		"component-compound":           strings.Replace(valid, "ɵcmp=", "ɵcmp+=", 1),
		"component-directive":          strings.Replace(valid, "ɵcmp", "ɵdir", 1),
		"component-prefix":             strings.Replace(valid, "ɵcmp", "otherɵcmp", 1),
		"component-suffix":             strings.Replace(valid, "ɵcmp", "ɵcmpExtra", 1),
		"component-case":               strings.Replace(valid, "ɵcmp", "ɵCmp", 1),
		"component-bad-escape":         strings.Replace(valid, "ɵcmp", `\u0276cmp`, 1),
		"component-escaped-suffix":     strings.Replace(valid, "ɵcmp", `\u0275cmpExtra`, 1),
		"component-double-escape":      strings.Replace(valid, "ɵcmp", `\\u0275cmp`, 1),
		"component-escaped-comparison": strings.Replace(valid, "ɵcmp=", `\u0275cmp===`, 1),
		"component-bracket":            strings.Replace(valid, ".ɵcmp", `["ɵcmp"]`, 1),
		"component-static-field":       angularContextKey + `class C{static ɵcmp=define({type:C})}` + angularHostVersionArray,
		"component-nested-target":      strings.Replace(valid, "Component.ɵcmp", "other.Component.ɵcmp", 1),
		"component-non-call":           strings.Replace(valid, "runtime.define({type:Component})", "metadata", 1),
		"component-no-metadata":        strings.Replace(valid, "({type:Component})", "()", 1),
		"component-no-type":            strings.Replace(valid, "{type:Component}", "{other:Component}", 1),
		"component-empty-type":         strings.Replace(valid, "{type:Component}", "{type:}", 1),
		"component-type-call":          strings.Replace(valid, "{type:Component}", "{type:getComponent()}", 1),
		"version-key-suffix":           strings.Replace(valid, "ng-version", "ng-version-extra", 1),
		"version-key-prefix":           strings.Replace(valid, "ng-version", "data-ng-version", 1),
		"version-key-case":             strings.Replace(valid, "ng-version", "NG-VERSION", 1),
		"version-object":               angularContextKey + angularComponentDefinition + `const attrs={"ng-version":"20.3.0"};`,
		"version-unquoted":             angularContextKey + angularComponentDefinition + `const attrs=["ng-version",20.3];`,
		"version-extra-element":        strings.Replace(valid, `"20.3.0"]`, `"20.3.0","extra"]`, 1),
		"version-reversed":             strings.Replace(valid, `["ng-version","20.3.0"]`, `["20.3.0","ng-version"]`, 1),
		"version-unclosed":             strings.Replace(valid, `"20.3.0"]`, `"20.3.0"`, 1),
	}
	for _, version := range []string{"", "1.8.3", "020.3.0", "20.03.0", "20.3.00", "20.3", "v20.3.0", "20.3.0-next.1", "20.3.0+custom", "0.0.0-PLACEHOLDER", "20x3x0", " 20.3.0"} {
		cases["version/"+version] = strings.Replace(valid, "20.3.0", version, 1)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}); len(got) != 0 {
				t.Fatalf("near miss produced findings=%+v", got)
			}
		})
	}
}

func TestAngularRuntimeIsolationAndEvidence(t *testing.T) {
	engine := bundledEngine(t)
	valid := angularContextKey + angularComponentDefinition + angularHostVersionArray
	for name, input := range map[string]detect.Input{
		"inline-html":       {HTML: []byte("<script>" + valid + "</script>")},
		"headers-cookies":   {Headers: http.Header{"X-Marker": {valid}}, CookieNames: []string{valid}},
		"css":               {Assets: []detect.Asset{cssAsset("https://example.test/file", valid)}},
		"empty-url":         {Assets: []detect.Asset{scriptAsset("", valid)}},
		"split-files":       {Assets: []detect.Asset{scriptAsset("https://example.test/one", angularContextKey+angularComponentDefinition), scriptAsset("https://example.test/two", angularHostVersionArray)}},
		"split-three-files": {Assets: []detect.Asset{scriptAsset("https://example.test/one", angularContextKey), scriptAsset("https://example.test/two", angularComponentDefinition), scriptAsset("https://example.test/three", angularHostVersionArray)}},
		"split-kinds":       {Assets: []detect.Asset{scriptAsset("https://example.test/one", angularContextKey+angularComponentDefinition), cssAsset("https://example.test/two", angularHostVersionArray)}},
		"split-page-asset":  {HTML: []byte(angularContextKey), Assets: []detect.Asset{scriptAsset("https://example.test/file", angularComponentDefinition+angularHostVersionArray)}},
		"filename-only":     {Assets: []detect.Asset{scriptAsset("https://example.test/angular.js", "generic")}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(input); len(got) != 0 {
				t.Fatalf("isolated indicators produced findings=%+v", got)
			}
		})
	}
	one, two := "https://example.test/z?private-token=1", "https://example.test/a"
	input := detect.Input{
		HTML:    []byte(angularHostTag),
		Headers: http.Header{"Server": {"nginx/1.26.2"}, "X-Powered-By": {"Next.js"}},
		Assets:  []detect.Asset{scriptAsset(one, valid+valid), scriptAsset(two, valid), scriptAsset(one, valid)},
	}
	got := engine.Detect(input)
	if len(got) != 3 || got[0].ID != "angular" || got[0].State != detect.Inferred || got[1].ID != "nextjs" || got[1].State != detect.Detected || got[2].ID != "nginx" || got[2].State != detect.Detected {
		t.Fatalf("mixed findings=%+v", got)
	}
	e := got[0].Evidence
	if len(e) != 3 || e[0].RuleID != "asset-component-runtime" || e[0].AssetURL != one || e[1].RuleID != "asset-component-runtime" || e[1].AssetURL != two || e[2].RuleID != "server-host-attributes" || e[2].AssetURL != "" {
		t.Fatalf("coexisting evidence=%+v", e)
	}
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Error("unstable evidence")
	}
	got[0].Evidence[0].AssetURL = "changed"
	got[0].Evidence[0].Signals[0].Source = "changed"
	if again := engine.Detect(input); again[0].Evidence[0].AssetURL != one || again[0].Evidence[0].Signals[0].Source != detect.AssetJavaScript {
		t.Error("shared evidence across calls")
	}
	if got := engine.Detect(detect.Input{}); len(got) != 0 {
		t.Fatal("retained evidence across scans")
	}
}
