package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const lazysizesConfig = `a=w.lazySizesConfig||w.lazysizesConfig||{};`
const lazysizesAPI = `{cfg:a,autoSizer:b,loader:c,init:d,uP:e,aC:f,rC:g,hC:h,fire:i,gW:j}`

func TestLazySizesCoreAssets(t *testing.T) {
	engine := bundledEngine(t)
	valid := lazysizesConfig + "var core=" + lazysizesAPI + ";"
	cases := map[string]string{
		"compact-short-api":  valid,
		"frame-helper":       strings.Replace(valid, "gW:j}", "gW:j,rAF:k}", 1),
		"trailing-comma":     strings.Replace(valid, "gW:j}", "gW:j,}", 1),
		"for-in-initializer": "for(p in " + strings.TrimSuffix(lazysizesConfig, ";") + ",defaults){};var core=" + lazysizesAPI + ";",
		"renamed-spaced": "const $settings = $browser . lazySizesConfig || $browser . lazysizesConfig || { };\n" +
			"var core = { cfg : $settings, autoSizer : $sizer, loader : $loader, init : $init, uP : $update, aC : $add, rC : $remove, hC : $has, fire : $fire, gW : $width, rAF : $frame, };",
		"reverse-indicator-order": "var core=" + lazysizesAPI + ";" + lazysizesConfig,
		"repeated":                valid + valid,
		// Matching is textual: these do not assert execution or JS scope.
		"commented":              "/* " + valid + " */",
		"different-receivers":    strings.Replace(valid, "w.lazysizesConfig", "other.lazysizesConfig", 1),
		"different-config-value": strings.Replace(valid, "cfg:a", "cfg:other", 1),
	}
	for _, file := range []string{"lazysizes-core.js", "lazysizes-core.min.js"} {
		cases[file] = string(htmlFixture(t, file))
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			url := "https://example.test/renamed?private-token=1"
			got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, body)}})
			if len(got) != 1 || got[0].ID != "lazysizes" || got[0].Name != "lazySizes" || got[0].Category != detect.JSLibrary || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
				t.Fatalf("findings=%+v", got)
			}
			e := got[0].Evidence[0]
			if e.RuleID != "asset-core-runtime" || e.AssetURL != url || e.StyleBlock != 0 || e.InferredFrom != "" || e.Description == "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}) {
				t.Fatalf("evidence=%+v", e)
			}
			if strings.Contains(e.Description, "private-token") || strings.Contains(e.Description, "cfg:") {
				t.Error("evidence description contains captured data")
			}
		})
	}
}

func TestLazySizesNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	valid := lazysizesConfig + "var core=" + lazysizesAPI + ";"
	cases := map[string]string{
		"empty":              "",
		"config-only":        lazysizesConfig,
		"api-only":           "var core=" + lazysizesAPI + ";",
		"banner-only":        "/*! lazysizes - v5.3.1 */",
		"generic-lazyload":   `img.loading="lazy"; observer.observe(img);`,
		"consumer-config":    `window.lazySizesConfig={init:false}; lazySizes.init();`,
		"api-usage":          `lazySizes.loader.unveil(img); lazySizes.autoSizer.checkElems();`,
		"config-comparison":  strings.Replace(valid, "a=w.", "a===w.", 1),
		"compound-config":    strings.Replace(valid, "a=w.", "a+=w.", 1),
		"qualified-target":   "object." + valid,
		"qualified-receiver": strings.Replace(valid, "a=w.", "a=global.w.", 1),
		"bracket-config":     strings.Replace(valid, "w.lazySizesConfig", `w["lazySizesConfig"]`, 1),
		"missing-alias":      strings.Replace(valid, "w.lazysizesConfig||", "", 1),
		"wrong-config-case":  strings.Replace(valid, "lazySizesConfig", "lazysizesconfig", 1),
		"config-suffix":      strings.Replace(valid, "lazySizesConfig", "lazySizesConfigOther", 1),
		"nonempty-fallback":  strings.Replace(valid, "||{}", "||{init:true}", 1),
		"fallback-member":    strings.Replace(valid, "||{};", "||{}.settings;", 1),
		"fallback-continued": strings.Replace(valid, "||{};", "||{}||another;", 1),
		"config-comment":     strings.Replace(valid, "||w.lazysizesConfig", "||/* config */w.lazysizesConfig", 1),
		"missing-loader":     strings.Replace(valid, "loader:c,", "", 1),
		"missing-helper":     strings.Replace(valid, "hC:h,", "", 1),
		"wrong-api-case":     strings.Replace(valid, "autoSizer:", "autosizer:", 1),
		"quoted-api-key":     strings.Replace(valid, "cfg:", `"cfg":`, 1),
		"api-key-suffix":     strings.Replace(valid, "cfg:", "mycfg:", 1),
		"reordered-fields":   strings.Replace(valid, "autoSizer:b,loader:c", "loader:c,autoSizer:b", 1),
		"nested-field":       strings.Replace(valid, "loader:c", "loader:{value:c}", 1),
		"called-value":       strings.Replace(valid, "loader:c", "loader:c()", 1),
		"literal-value":      strings.Replace(valid, "cfg:a", "cfg:0", 1),
		"api-comment":        strings.Replace(valid, "{cfg:", "{/* core */cfg:", 1),
		"extra-field":        strings.Replace(valid, "gW:j}", "gW:j,other:k}", 1),
		"open-object":        strings.TrimSuffix(valid, "};"),
		"split-objects":      strings.Replace(valid, "init:d,uP:e", "init:d};var helpers={uP:e", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestLazySizesSourceIsolationAndCoexistence(t *testing.T) {
	engine := bundledEngine(t)
	valid := lazysizesConfig + "var core=" + lazysizesAPI + ";"
	one, two := "https://example.test/one", "https://example.test/two"
	for name, input := range map[string]detect.Input{
		"html":             {HTML: []byte("<script>" + valid + "</script>")},
		"headers-cookies":  {Headers: http.Header{"X-Example": {valid}}, CookieNames: []string{valid}},
		"css":              {Assets: []detect.Asset{cssAsset(one, valid)}},
		"inline-css":       {InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(valid)}}},
		"empty-url":        {Assets: []detect.Asset{scriptAsset("", valid)}},
		"filename-only":    {Assets: []detect.Asset{scriptAsset("https://example.test/lazysizes.min.js", "generic")}},
		"split-files":      {Assets: []detect.Asset{scriptAsset(one, lazysizesConfig), scriptAsset(two, lazysizesAPI)}},
		"same-url-parts":   {Assets: []detect.Asset{scriptAsset(one, lazysizesConfig), scriptAsset(one, lazysizesAPI)}},
		"split-kinds":      {Assets: []detect.Asset{scriptAsset(one, lazysizesConfig), cssAsset(two, lazysizesAPI)}},
		"split-page-asset": {HTML: []byte(lazysizesConfig), Assets: []detect.Asset{scriptAsset(one, lazysizesAPI)}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(input); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
	input := detect.Input{
		Headers: http.Header{"Server": {"nginx"}},
		Assets: []detect.Asset{
			scriptAsset(one, valid+jqueryPrototype+jqueryExpando),
			scriptAsset(two, valid), scriptAsset(one, valid),
		},
	}
	got := engine.Detect(input)
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
	}
	if !reflect.DeepEqual(ids, []string{"jquery", "lazysizes", "nginx"}) || got[1].State != detect.Inferred || len(got[1].Evidence) != 2 || got[1].Evidence[0].AssetURL != one || got[1].Evidence[1].AssetURL != two {
		t.Fatalf("findings=%+v", got)
	}
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Fatal("unstable findings/evidence order")
	}
	got[1].Evidence[0].AssetURL = "changed"
	got[1].Evidence[0].Signals[0].Source = detect.HTML
	if again := engine.Detect(input); again[1].Evidence[0].AssetURL != one || again[1].Evidence[0].Signals[0].Source != detect.AssetJavaScript {
		t.Fatal("returned evidence mutated subsequent scans")
	}
	if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
		t.Fatalf("findings leaked into later scan: %+v", empty)
	}
}
