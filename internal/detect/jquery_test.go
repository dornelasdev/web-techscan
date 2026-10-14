package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const jqueryPrototype = `q.fn=q.prototype={jquery:v,constructor:q,length:0};`
const jqueryExpando = `q.extend({expando:"jQuery"+(v+Math.random()).replace(/\D/g,"")});`

func TestJQueryCoreRuntime(t *testing.T) {
	engine := bundledEngine(t)
	valid := jqueryPrototype + jqueryExpando
	cases := map[string]string{
		"compact":          valid,
		"single-quotes":    strings.ReplaceAll(valid, `"`, `'`),
		"spacing-renamed":  "library \n. fn = library . prototype = { jquery : $version, constructor : library, length : 0 };\nlibrary.extend({ expando : 'jQuery' + ( $version + Math . random ( ) ) . replace ( /\\D/g , '' ) });",
		"reversed":         jqueryExpando + jqueryPrototype,
		"other-properties": strings.Replace(valid, "length:0}", "length:0,toArray:function(){return [];}}", 1),
		"repeated":         valid + valid,
		// This engine observes code-shaped text, not execution or JS scope.
		"commented":             "/* " + valid + " */",
		"different-identifiers": strings.Replace(valid, "q.prototype", "other.prototype", 1),
	}
	for _, name := range []string{"jquery-core.js", "jquery-core.min.js"} {
		cases[name] = string(htmlFixture(t, name))
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			url := "https://example.test/renamed?private-token=1"
			got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, body)}})
			if len(got) != 1 || got[0].ID != "jquery" || got[0].Name != "jQuery" || got[0].Category != detect.JSLibrary || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
				t.Fatalf("findings=%+v", got)
			}
			e := got[0].Evidence[0]
			if e.RuleID != "asset-core-runtime" || e.AssetURL != url || e.InferredFrom != "" || e.Description == "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}) {
				t.Fatalf("evidence=%+v", e)
			}
			for _, raw := range []string{"private-token", "Math.random", "3.7.1", "4.0.0"} {
				if strings.Contains(e.Description, raw) {
					t.Errorf("raw asset/version data in description: %q", e.Description)
				}
			}
		})
	}
}

func TestJQueryCoreRuntimeNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	valid := jqueryPrototype + jqueryExpando
	cases := map[string]string{
		"empty":                 "",
		"prototype-only":        jqueryPrototype,
		"expando-only":          jqueryExpando,
		"banner-only":           `/*! jQuery v4.0.0 | jquery.com/license */`,
		"bare-api-names":        `jQuery $ fn prototype jquery expando Math.random`,
		"generic-usage":         `$(document).ready(function(){$(".btn").on("click",handler);});`,
		"plugin-shaped":         `q.fn.plugin=function(){return this;};` + jqueryExpando,
		"prototype-read":        `var p=q.fn===q.prototype;` + jqueryExpando,
		"no-fn-assignment":      strings.Replace(valid, "q.fn=", "", 1),
		"fn-comparison":         strings.Replace(valid, ".fn=", ".fn===", 1),
		"compound-assignment":   strings.Replace(valid, ".fn=", ".fn+=", 1),
		"qualified-receiver":    "module." + valid,
		"bracket-fn":            strings.Replace(valid, "q.fn", `q["fn"]`, 1),
		"prototype-suffix":      strings.Replace(valid, ".prototype=", ".prototypeOther=", 1),
		"quoted-jquery-key":     strings.Replace(valid, "{jquery:", `{"jquery":`, 1),
		"wrong-key-case":        strings.Replace(valid, "{jquery:", "{jQuery:", 1),
		"prefixed-key":          strings.Replace(valid, "{jquery:", "{otherjquery:", 1),
		"literal-version-value": strings.Replace(valid, "jquery:v", `jquery:"4.0.0"`, 1),
		"missing-constructor":   strings.Replace(valid, "constructor:q,", "", 1),
		"missing-length":        strings.Replace(valid, ",length:0", "", 1),
		"nonzero-length":        strings.Replace(valid, "length:0", "length:1", 1),
		"decimal-length":        strings.Replace(valid, "length:0", "length:0.0", 1),
		"reordered-properties":  strings.Replace(valid, "jquery:v,constructor:q", "constructor:q,jquery:v", 1),
		"expando-key-suffix":    strings.Replace(valid, "expando:", "expandoOther:", 1),
		"wrong-product-case":    strings.Replace(valid, `"jQuery"`, `"jquery"`, 1),
		"product-suffix":        strings.Replace(valid, `"jQuery"`, `"jQueryOther"`, 1),
		"quoted-expando-key":    strings.Replace(valid, "expando:", `"expando":`, 1),
		"expando-read":          jqueryPrototype + `var e=q.expando;`,
		"no-random-call":        strings.Replace(valid, "Math.random()", "Math.random", 1),
		"random-with-argument":  strings.Replace(valid, "Math.random()", "Math.random(1)", 1),
		"qualified-math":        strings.Replace(valid, "Math.random()", "global.Math.random()", 1),
		"wrong-regexp":          strings.Replace(valid, `/\D/g`, `/\d/g`, 1),
		"wrong-flags":           strings.Replace(valid, `/\D/g`, `/\D/gi`, 1),
		"nonempty-replacement":  strings.Replace(valid, `,""`, `,"x"`, 1),
		"changed-call":          strings.Replace(valid, ".replace(", ".replaceAll(", 1),
		"string-escape":         strings.Replace(valid, `"jQuery"`, `"\u006aQuery"`, 1),
		"interleaved-comment":   strings.Replace(valid, "{jquery:", "{/* example */jquery:", 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestJQueryCoreRuntimeIsolationAndCoexistence(t *testing.T) {
	engine := bundledEngine(t)
	valid := jqueryPrototype + jqueryExpando
	for name, input := range map[string]detect.Input{
		"inline-html":           {HTML: []byte("<script>" + valid + "</script>")},
		"headers-cookies":       {Headers: http.Header{"X-Marker": {valid}}, CookieNames: []string{valid}},
		"css":                   {Assets: []detect.Asset{cssAsset("https://example.test/file", valid)}},
		"empty-url":             {Assets: []detect.Asset{scriptAsset("", valid)}},
		"split-files":           {Assets: []detect.Asset{scriptAsset("https://example.test/one", jqueryPrototype), scriptAsset("https://example.test/two", jqueryExpando)}},
		"same-url-split-bodies": {Assets: []detect.Asset{scriptAsset("https://example.test/one", jqueryPrototype), scriptAsset("https://example.test/one", jqueryExpando)}},
		"split-kinds":           {Assets: []detect.Asset{scriptAsset("https://example.test/one", jqueryPrototype), cssAsset("https://example.test/two", jqueryExpando)}},
		"split-page-asset":      {HTML: []byte(jqueryPrototype), Assets: []detect.Asset{scriptAsset("https://example.test/file", jqueryExpando)}},
		"filename-only":         {Assets: []detect.Asset{scriptAsset("https://example.test/jquery-4.0.0.min.js", "generic")}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(input); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
	one, two := "https://example.test/one", "https://example.test/two"
	input := detect.Input{
		Headers: http.Header{"X-Powered-By": {"Next.js"}, "Server": {"nginx"}},
		Assets: []detect.Asset{
			scriptAsset(one, valid+reactClientAssignment+reactElementSymbol),
			scriptAsset(two, valid), scriptAsset(one, valid),
		},
	}
	got := engine.Detect(input)
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
	}
	if !reflect.DeepEqual(ids, []string{"jquery", "nextjs", "nginx", "react"}) || got[0].State != detect.Inferred || len(got[0].Evidence) != 2 || got[0].Evidence[0].AssetURL != one || got[0].Evidence[1].AssetURL != two || got[1].State != detect.Detected || got[2].State != detect.Detected || got[3].State != detect.Inferred {
		t.Fatalf("mixed findings=%+v", got)
	}
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Error("unstable findings/evidence")
	}
	got[0].Evidence[0].AssetURL = "changed"
	if again := engine.Detect(input); again[0].Evidence[0].AssetURL != one {
		t.Error("shared evidence across scans")
	}
	if len(engine.Detect(detect.Input{})) != 0 {
		t.Error("retained findings across scans")
	}
}
