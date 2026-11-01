package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const modernizr3Config = `_config:{classPrefix:"",enableClasses:!0,enableJSClass:!0,usePrefixes:!0}`
const modernizr3Registration = `addTest:function(a,b,c){q.push({name:a,fn:b,options:c})},addAsyncTest:function(a){q.push({name:null,fn:a})}`

func TestModernizrV3CoreAssets(t *testing.T) {
	engine := bundledEngine(t)
	valid := "var core={" + modernizr3Config + "," + modernizr3Registration + "};"
	cases := map[string]string{
		"compact":         valid,
		"normal-booleans": strings.ReplaceAll(valid, "!0", "true"),
		"disabled-flags":  strings.ReplaceAll(valid, "!0", "!1"),
		"false-flags":     strings.ReplaceAll(valid, "!0", "false"),
		"custom-prefix":   strings.Replace(valid, `classPrefix:""`, `classPrefix:"custom-"`, 1),
		"escaped-prefix":  strings.Replace(valid, `classPrefix:""`, `classPrefix:"sample\"prefix\\tail"`, 1),
		"quoted-keys":     strings.NewReplacer("_config:", `"_config":`, "classPrefix:", `'classPrefix':`, "enableClasses:", `"enableClasses":`, "enableJSClass:", `'enableJSClass':`, "usePrefixes:", `"usePrefixes":`, "addTest:", `'addTest':`, "addAsyncTest:", `"addAsyncTest":`, "name:", `'name':`, "fn:", `"fn":`, "options:", `'options':`).Replace(valid),
		"trailing-commas": strings.NewReplacer("usePrefixes:!0}", "usePrefixes:!0,}", "options:c}", "options:c,}", "fn:a}", "fn:a,}").Replace(valid),
		"spaced": "var proto = { _config : { classPrefix : 'app-', enableClasses : true, enableJSClass : ! 1, usePrefixes : false },\n" +
			"addTest : function ( $name, $fn, $options ) { $queue . push ( { name : $name, fn : $fn, options : $options } ); },\n" +
			"addAsyncTest : function ( $fn ) { $queue . push ( { name : null, fn : $fn } ); } };",
		"comments-around-groups": "var proto={/* metadata */" + modernizr3Config + ",/* methods */" + modernizr3Registration + "};",
		"reversed-groups":        "var proto={" + modernizr3Registration + "," + modernizr3Config + "};",
		"repeated":               valid + valid,
		// Same-capture text does not establish common scope, identifier
		// equality, JavaScript validity, or execution.
		"different-objects": "var one={" + modernizr3Config + "};var two={" + modernizr3Registration + "};",
		"different-queues":  strings.Replace(valid, "{q.push({name:null", "{other.push({name:null", 1),
		"commented":         "/* " + valid + " */",
	}
	for _, file := range []string{"modernizr-v3-core.js", "modernizr-v3-core.min.js"} {
		cases[file] = string(htmlFixture(t, file))
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			url := "https://example.test/renamed?private-query"
			got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, body)}})
			if len(got) != 1 || got[0].ID != "modernizr" || got[0].Name != "Modernizr" || got[0].Category != detect.JSLibrary || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
				t.Fatalf("findings=%+v", got)
			}
			e := got[0].Evidence[0]
			if e.RuleID != "asset-v3-core-registration" || e.AssetURL != url || e.StyleBlock != 0 || e.InferredFrom != "" || e.Description == "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}) {
				t.Fatalf("evidence=%+v", e)
			}
			for _, raw := range []string{"private-", "_config", "3.6.0", "3.11.2", "3.12.0"} {
				if strings.Contains(e.Description, raw) {
					t.Errorf("raw content/version in evidence: %q", raw)
				}
			}
		})
	}
}

func TestModernizrV3NearMisses(t *testing.T) {
	engine := bundledEngine(t)
	valid := "var core={" + modernizr3Config + "," + modernizr3Registration + "};"
	cases := map[string]string{
		"empty":                 "",
		"config-only":           "var core={" + modernizr3Config + "};",
		"registration-only":     "var core={" + modernizr3Registration + "};",
		"banner-version-only":   `/*! Modernizr 3.13.1 */ var p={_version:"3.13.1"};`,
		"usage":                 `Modernizr.addTest("custom",true);Modernizr.addAsyncTest(function(){});`,
		"config-and-usage":      "var options={" + modernizr3Config + `};Modernizr.addTest("custom",true);`,
		"wrong-config-case":     strings.Replace(valid, "_config:", "_Config:", 1),
		"config-key-suffix":     strings.Replace(valid, "_config:", "my_config:", 1),
		"qualified-config":      strings.Replace(valid, "_config:", "other._config:", 1),
		"unkeyed-config":        strings.Replace(valid, "_config:", "", 1),
		"missing-class-prefix":  strings.Replace(valid, `classPrefix:"",`, "", 1),
		"computed-prefix":       strings.Replace(valid, `classPrefix:""`, "classPrefix:prefix", 1),
		"missing-enable-js":     strings.Replace(valid, "enableJSClass:!0,", "", 1),
		"wrong-field-case":      strings.Replace(valid, "enableClasses:", "enableclasses:", 1),
		"string-flag":           strings.Replace(valid, "usePrefixes:!0", `usePrefixes:"true"`, 1),
		"numeric-flag":          strings.Replace(valid, "usePrefixes:!0", "usePrefixes:1", 1),
		"identifier-flag":       strings.Replace(valid, "usePrefixes:!0", "usePrefixes:flag", 1),
		"continued-flag":        strings.Replace(valid, "usePrefixes:!0", "usePrefixes:!0||flag", 1),
		"extra-config-field":    strings.Replace(valid, "usePrefixes:!0}", "usePrefixes:!0,other:true}", 1),
		"open-config":           strings.Replace(valid, "usePrefixes:!0}", "usePrefixes:!0", 1),
		"reordered-config":      strings.Replace(valid, "enableClasses:!0,enableJSClass:!0", "enableJSClass:!0,enableClasses:!0", 1),
		"config-comment":        strings.Replace(valid, "enableClasses:!0,", "enableClasses:!0,/* comment */", 1),
		"missing-async":         "var core={" + modernizr3Config + ",addTest:function(a,b,c){q.push({name:a,fn:b,options:c})}};",
		"missing-sync":          "var core={" + modernizr3Config + ",addAsyncTest:function(a){q.push({name:null,fn:a})}};",
		"wrong-method-case":     strings.Replace(valid, "addAsyncTest:", "addAsynctest:", 1),
		"method-key-suffix":     strings.Replace(valid, "addTest:", "myaddTest:", 1),
		"short-sync-parameters": strings.Replace(valid, "function(a,b,c)", "function(a,b)", 1),
		"extra-async-parameter": strings.Replace(valid, "addAsyncTest:function(a)", "addAsyncTest:function(a,b)", 1),
		"named-function":        strings.Replace(valid, "addTest:function(", "addTest:function register(", 1),
		"missing-options":       strings.Replace(valid, ",options:c", "", 1),
		"wrong-record-order":    strings.Replace(valid, "name:a,fn:b", "fn:b,name:a", 1),
		"qualified-queue":       strings.Replace(valid, "{q.push", "{other.q.push", 1),
		"queue-unshift":         strings.Replace(valid, "q.push", "q.unshift", 1),
		"async-nonnull-name":    strings.Replace(valid, "name:null", "name:a", 1),
		"async-missing-fn":      strings.Replace(valid, "name:null,fn:a", "name:null", 1),
		"extra-body-statement":  strings.Replace(valid, "{q.push", "{notify();q.push", 1),
		"between-methods":       strings.Replace(valid, "},addAsyncTest", "},extra:1,addAsyncTest", 1),
		"method-comment":        strings.Replace(valid, "},addAsyncTest", "},/* comment */addAsyncTest", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestModernizrV3SourceIsolationAndV2Evidence(t *testing.T) {
	engine := bundledEngine(t)
	v2 := modernizrFactory + modernizrPrefixes
	v3 := "var core={" + modernizr3Config + "," + modernizr3Registration + "};"
	a, b, c := "https://example.test/v2", "https://example.test/v3", "https://example.test/both"
	for name, input := range map[string]detect.Input{
		"inline-js":           {HTML: []byte("<script>" + v3 + "</script>")},
		"headers-cookies":     {Headers: http.Header{"X-Example": {v3}}, CookieNames: []string{v3}},
		"css":                 {Assets: []detect.Asset{cssAsset(a, v3)}},
		"inline-css":          {InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(v3)}}},
		"empty-url":           {Assets: []detect.Asset{scriptAsset("", v3)}},
		"filename":            {Assets: []detect.Asset{scriptAsset("https://example.test/modernizr-3.13.1.min.js", "generic")}},
		"split-files":         {Assets: []detect.Asset{scriptAsset(a, modernizr3Config), scriptAsset(b, modernizr3Registration)}},
		"same-url-parts":      {Assets: []detect.Asset{scriptAsset(a, modernizr3Config), scriptAsset(a, modernizr3Registration)}},
		"split-kinds":         {Assets: []detect.Asset{scriptAsset(a, modernizr3Config), cssAsset(b, modernizr3Registration)}},
		"split-page-asset":    {HTML: []byte(modernizr3Config), Assets: []detect.Asset{scriptAsset(a, modernizr3Registration)}},
		"cross-rule-partials": {Assets: []detect.Asset{scriptAsset(a, modernizrFactory+modernizr3Config), scriptAsset(b, modernizrPrefixes+modernizr3Registration)}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(input); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
	input := detect.Input{Headers: http.Header{"Server": {"nginx"}}, Assets: []detect.Asset{
		scriptAsset(a, v2+jqueryPrototype+jqueryExpando+lazysizesConfig+"var core="+lazysizesAPI+";"),
		scriptAsset(b, v3), scriptAsset(c, v2+v3), scriptAsset(b, v3), cssAsset("https://example.test/decoy.css", v3),
	}}
	got := engine.Detect(input)
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
	}
	if !reflect.DeepEqual(ids, []string{"jquery", "lazysizes", "modernizr", "nginx"}) || got[2].State != detect.Inferred || len(got[2].Evidence) != 4 {
		t.Fatalf("findings=%+v", got)
	}
	for i, expected := range []struct{ rule, url string }{{"asset-v2-core-runtime", a}, {"asset-v2-core-runtime", c}, {"asset-v3-core-registration", b}, {"asset-v3-core-registration", c}} {
		e := got[2].Evidence[i]
		if e.RuleID != expected.rule || e.AssetURL != expected.url || e.InferredFrom != "" || e.StyleBlock != 0 {
			t.Fatalf("evidence=%+v want=%+v", e, expected)
		}
	}
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Fatal("unstable evidence order")
	}
	got[2].Evidence[2].AssetURL = "changed"
	got[2].Evidence[2].Signals[0].Source = detect.HTML
	if next := engine.Detect(input); next[2].Evidence[2].AssetURL != b || next[2].Evidence[2].Signals[0].Source != detect.AssetJavaScript {
		t.Fatal("mutable evidence leaked into another scan")
	}
	if len(engine.Detect(detect.Input{})) != 0 {
		t.Fatal("findings leaked into empty scan")
	}
}
