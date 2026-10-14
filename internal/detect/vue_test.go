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

const vueRuntimeFlag = `g().__VUE__=!0;`
const vueAppAssignment = `r.__vue_app__=a;`
const vueFragmentSymbol = `Symbol.for("v-fgt");`

func TestVueRendererRuntime(t *testing.T) {
	engine := bundledEngine(t)
	cases := map[string]string{
		"compact":         vueRuntimeFlag + vueAppAssignment + vueFragmentSymbol,
		"bare-receiver":   `target.__VUE__=true;` + vueAppAssignment + vueFragmentSymbol,
		"spacing":         "getTarget \n( ) . __VUE__ = ! 0 ;\ncontainer . __vue_app__ = app ;\nSymbol . for ( 'v-fgt' )",
		"renamed":         `$().__VUE__=!0;_root.__vue_app__=$app;` + vueFragmentSymbol,
		"comma-separator": `g().__VUE__=!0,r.__vue_app__=a,` + vueFragmentSymbol,
		"end-of-body":     vueFragmentSymbol + vueAppAssignment + `g().__VUE__=true`,
		"reversed":        vueFragmentSymbol + vueAppAssignment + vueRuntimeFlag,
		"closing-brace":   `function m(){r.__vue_app__=a}` + vueFragmentSymbol + vueRuntimeFlag,
		// Static matching cannot establish execution. Copied/commented
		// markers remain a supported inference, not a direct detection.
		"commented": "/* " + vueRuntimeFlag + vueAppAssignment + vueFragmentSymbol + " */",
	}
	for _, name := range []string{"vue-3-renderer.js", "vue-3-renderer.min.js"} {
		body, err := os.ReadFile("testdata/coverage/" + name)
		if err != nil {
			t.Fatal(err)
		}
		cases[name] = string(body)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			url := "https://example.test/renamed?private-token=1"
			got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, body)}})
			if len(got) != 1 || got[0].ID != "vue" || got[0].Name != "Vue" || got[0].Category != detect.JSFramework || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
				t.Fatalf("findings=%+v", got)
			}
			e := got[0].Evidence[0]
			if e.RuleID != "asset-renderer-runtime" || e.AssetURL != url || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}) {
				t.Fatalf("evidence=%+v", e)
			}
			if strings.Contains(e.Description, "private-") || strings.Contains(e.Description, "__vue_app__") {
				t.Errorf("raw body/URL data in description: %q", e.Description)
			}
		})
	}
}

func TestVueRendererPartialMarkers(t *testing.T) {
	engine := bundledEngine(t)
	markers := []string{vueRuntimeFlag, vueAppAssignment, vueFragmentSymbol}
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprintf("subset-%d", mask), func(t *testing.T) {
			var body string
			for i, marker := range markers {
				if mask&(1<<i) != 0 {
					body += marker
				}
			}
			got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}})
			if mask != 7 {
				if len(got) != 0 {
					t.Fatalf("partial markers produced findings=%+v", got)
				}
			} else if len(got) != 1 || got[0].ID != "vue" || got[0].State != detect.Inferred {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestVueRendererNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	valid := vueRuntimeFlag + vueAppAssignment + vueFragmentSymbol
	cases := map[string]string{
		"bare-names":             `__VUE__ __vue_app__ v-fgt`,
		"generic-api":            `Vue.createApp({});document.getElementById("app");`,
		"legacy-like":            `Vue.version="2.7.16";vm._isVue=true;el.__vue__=vm;`,
		"flag-read":              `var x=g().__VUE__;` + vueAppAssignment + vueFragmentSymbol,
		"flag-comparison":        strings.Replace(valid, "__VUE__=", "__VUE__===", 1),
		"flag-compound":          strings.Replace(valid, "__VUE__=", "__VUE__|=", 1),
		"false-flag":             strings.Replace(valid, "=!0;", "=!1;", 1),
		"flag-value-suffix":      strings.Replace(valid, "=!0;", "=!01;", 1),
		"flag-true-suffix":       strings.Replace(valid, "=!0;", "=trueish;", 1),
		"flag-prefix":            strings.Replace(valid, ".__VUE__", ".other__VUE__", 1),
		"flag-suffix":            strings.Replace(valid, "__VUE__=", "__VUE__EXTRA=", 1),
		"flag-case":              strings.Replace(valid, "__VUE__", "__vue__", 1),
		"flag-bracket":           `g()["__VUE__"]=!0;` + vueAppAssignment + vueFragmentSymbol,
		"getter-with-argument":   strings.Replace(valid, "g()", "g(1)", 1),
		"app-read":               vueRuntimeFlag + `var x=r.__vue_app__;` + vueFragmentSymbol,
		"app-delete":             vueRuntimeFlag + `delete r.__vue_app__;` + vueFragmentSymbol,
		"app-comparison":         strings.Replace(valid, "__vue_app__=", "__vue_app__===", 1),
		"app-compound":           strings.Replace(valid, "__vue_app__=", "__vue_app__+=", 1),
		"app-prefix":             strings.Replace(valid, ".__vue_app__", ".other__vue_app__", 1),
		"app-suffix":             strings.Replace(valid, "__vue_app__=", "__vue_app__EXTRA=", 1),
		"app-case":               strings.Replace(valid, "__vue_app__", "__VUE_APP__", 1),
		"app-empty":              strings.Replace(valid, "__vue_app__=a;", "__vue_app__=;", 1),
		"app-quoted-value":       strings.Replace(valid, "__vue_app__=a;", `__vue_app__="app";`, 1),
		"app-bracket":            vueRuntimeFlag + `r["__vue_app__"]=a;` + vueFragmentSymbol,
		"symbol-prefix":          strings.Replace(valid, "Symbol.for", "OtherSymbol.for", 1),
		"symbol-member":          strings.Replace(valid, "Symbol.for", "other.Symbol.for", 1),
		"symbol-function-suffix": strings.Replace(valid, "Symbol.for", "Symbol.format", 1),
		"symbol-suffix":          strings.Replace(valid, "v-fgt", "v-fgt-extra", 1),
		"symbol-case":            strings.Replace(valid, "v-fgt", "V-FGT", 1),
		"symbol-not-call":        vueRuntimeFlag + vueAppAssignment + `"v-fgt";`,
		"text-symbol-only":       strings.Replace(valid, "v-fgt", "v-txt", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestVueRendererIsolationAndEvidence(t *testing.T) {
	engine := bundledEngine(t)
	valid := vueRuntimeFlag + vueAppAssignment + vueFragmentSymbol
	for name, input := range map[string]detect.Input{
		"inline-html":       {HTML: []byte("<script>" + valid + "</script>")},
		"headers-cookies":   {Headers: http.Header{"X-Marker": {valid}}, CookieNames: []string{valid}},
		"css":               {Assets: []detect.Asset{cssAsset("https://example.test/file", valid)}},
		"empty-url":         {Assets: []detect.Asset{scriptAsset("", valid)}},
		"split-files":       {Assets: []detect.Asset{scriptAsset("https://example.test/one", vueRuntimeFlag), scriptAsset("https://example.test/two", vueAppAssignment+vueFragmentSymbol)}},
		"split-three-files": {Assets: []detect.Asset{scriptAsset("https://example.test/one", vueRuntimeFlag), scriptAsset("https://example.test/two", vueAppAssignment), scriptAsset("https://example.test/three", vueFragmentSymbol)}},
		"split-kinds":       {Assets: []detect.Asset{scriptAsset("https://example.test/one", vueRuntimeFlag+vueAppAssignment), cssAsset("https://example.test/two", vueFragmentSymbol)}},
		"split-page-asset":  {HTML: []byte(vueRuntimeFlag), Assets: []detect.Asset{scriptAsset("https://example.test/file", vueAppAssignment+vueFragmentSymbol)}},
		"filename-only":     {Assets: []detect.Asset{scriptAsset("https://example.test/vue-3.5.13.js", "generic")}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(input); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
	// Nuxt and Vue are independent findings; neither implies a language.
	input := detect.Input{Headers: http.Header{"X-Powered-By": {"Nuxt"}}}
	if got := engine.Detect(input); len(got) != 1 || got[0].ID != "nuxt" {
		t.Fatalf("header-only findings=%+v", got)
	}
	one, two := "https://example.test/two", "https://example.test/one"
	input.Assets = []detect.Asset{scriptAsset(one, valid+valid), scriptAsset(two, valid), scriptAsset(one, valid)}
	got := engine.Detect(input)
	if len(got) != 2 || got[0].ID != "nuxt" || got[0].State != detect.Detected || got[1].ID != "vue" || got[1].State != detect.Inferred || len(got[1].Evidence) != 2 || got[1].Evidence[0].AssetURL != one || got[1].Evidence[1].AssetURL != two {
		t.Fatalf("mixed findings=%+v", got)
	}
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Error("unstable evidence")
	}
	got[1].Evidence[0].AssetURL = "changed"
	got[1].Evidence[0].Signals[0].Source = "changed"
	if again := engine.Detect(input); again[1].Evidence[0].AssetURL != one || again[1].Evidence[0].Signals[0].Source != detect.AssetJavaScript {
		t.Error("shared evidence across scans")
	}
	if got := engine.Detect(detect.Input{}); len(got) != 0 {
		t.Fatal("retained asset evidence across scans")
	}
}
