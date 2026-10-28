package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const modernizrFactory = `w.Modernizr=function(a,b,c){return {};};`
const modernizrPrefixes = `m._domPrefixes=p;m._cssomPrefixes=q;`

func TestModernizrV2CoreAssets(t *testing.T) {
	engine := bundledEngine(t)
	valid := modernizrFactory + modernizrPrefixes
	cases := map[string]string{
		"compact":               valid,
		"parenthesized-factory": `w.Modernizr=(function(a,b,c){return {};}(w,d));` + modernizrPrefixes,
		"comma-metadata":        modernizrFactory + `m._domPrefixes=p,m._cssomPrefixes=q,m.other=1;`,
		"metadata-at-eof":       modernizrFactory + strings.TrimSuffix(modernizrPrefixes, ";"),
		"reversed-indicators":   modernizrPrefixes + modernizrFactory,
		"renamed-spaced":        "$host . Modernizr = ( function ( $window, $document, $missing ) { return {}; }($host, $doc));\n$features . _domPrefixes = $dom ;\n$features . _cssomPrefixes = $css ;",
		"repeated":              valid + valid,
		// Textual markers do not establish execution, scope or identifier equality.
		"commented":           "/* " + valid + " */",
		"different-receivers": modernizrFactory + `one._domPrefixes=p;other._cssomPrefixes=q;`,
	}
	for _, file := range []string{"modernizr-v2-core.js", "modernizr-v2-core.min.js"} {
		cases[file] = string(htmlFixture(t, file))
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			url := "https://example.test/renamed?private-token=1"
			got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, body)}})
			if len(got) != 1 || got[0].ID != "modernizr" || got[0].Name != "Modernizr" || got[0].Category != detect.JSLibrary || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
				t.Fatalf("findings=%+v", got)
			}
			e := got[0].Evidence[0]
			if e.RuleID != "asset-v2-core-runtime" || e.AssetURL != url || e.StyleBlock != 0 || e.InferredFrom != "" || e.Description == "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}) {
				t.Fatalf("evidence=%+v", e)
			}
			for _, raw := range []string{"private-token", "_domPrefixes", "2.6.2", "2.8.3"} {
				if strings.Contains(e.Description, raw) {
					t.Errorf("raw capture/version data in evidence: %q", raw)
				}
			}
		})
	}
}

func TestModernizrV2NearMisses(t *testing.T) {
	engine := bundledEngine(t)
	valid := modernizrFactory + modernizrPrefixes
	cases := map[string]string{
		"empty":                "",
		"factory-only":         modernizrFactory,
		"metadata-only":        modernizrPrefixes,
		"banner-only":          "/*! Modernizr 2.8.3 */",
		"consumer-api":         `Modernizr.addTest("custom", true);if(Modernizr.flexbox)enableLayout();`,
		"feature-classes":      `document.documentElement.className="js flexbox no-webgl";`,
		"factory-comparison":   strings.Replace(valid, "Modernizr=", "Modernizr===", 1),
		"factory-compound":     strings.Replace(valid, "Modernizr=", "Modernizr+=", 1),
		"qualified-receiver":   "other." + valid,
		"wrong-product-case":   strings.Replace(valid, "Modernizr", "modernizr", 1),
		"product-suffix":       strings.Replace(valid, "Modernizr", "ModernizrOther", 1),
		"bracket-product":      strings.Replace(valid, "w.Modernizr", `w["Modernizr"]`, 1),
		"named-factory":        strings.Replace(valid, "function(", "function factory(", 1),
		"arrow-factory":        `w.Modernizr=(a,b,c)=>({});` + modernizrPrefixes,
		"two-parameters":       strings.Replace(valid, "(a,b,c)", "(a,b)", 1),
		"four-parameters":      strings.Replace(valid, "(a,b,c)", "(a,b,c,d)", 1),
		"rest-parameter":       strings.Replace(valid, "(a,b,c)", "(a,b,...c)", 1),
		"factory-no-body":      `w.Modernizr=function(a,b,c);` + modernizrPrefixes,
		"factory-comment":      strings.Replace(valid, "function(", "function/* factory */(", 1),
		"missing-dom-prefixes": modernizrFactory + `m._cssomPrefixes=q;`,
		"missing-css-prefixes": modernizrFactory + `m._domPrefixes=p;`,
		"metadata-read":        modernizrFactory + `use(m._domPrefixes,m._cssomPrefixes);`,
		"metadata-comparison":  strings.Replace(valid, "_domPrefixes=", "_domPrefixes===", 1),
		"css-comparison":       strings.Replace(valid, "_cssomPrefixes=", "_cssomPrefixes===", 1),
		"wrong-field-case":     strings.Replace(valid, "_domPrefixes", "_domprefixes", 1),
		"field-suffix":         strings.Replace(valid, "_cssomPrefixes", "_cssomPrefixesOther", 1),
		"bracket-field":        strings.Replace(valid, "m._domPrefixes", `m["_domPrefixes"]`, 1),
		"qualified-metadata":   modernizrFactory + "other." + modernizrPrefixes,
		"reordered-metadata":   modernizrFactory + `m._cssomPrefixes=q;m._domPrefixes=p;`,
		"separated-metadata":   modernizrFactory + `m._domPrefixes=p;other();m._cssomPrefixes=q;`,
		"metadata-comment":     strings.Replace(valid, "p;m.", "p;/* metadata */m.", 1),
		"literal-prefix-list":  strings.Replace(valid, "_domPrefixes=p", `_domPrefixes=["webkit"]`, 1),
		"called-prefix-value":  strings.Replace(valid, "_cssomPrefixes=q", "_cssomPrefixes=q()", 1),
		"continued-value":      strings.Replace(valid, "_cssomPrefixes=q;", "_cssomPrefixes=q.other;", 1),
		"prototype-shaped-v3":  `var p={_version:"3.13.1",_config:{enableClasses:true},_q:[]};var M=function(){};M.prototype=p;w.Modernizr=new M();`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestModernizrV2SourceIsolationAndCoexistence(t *testing.T) {
	engine := bundledEngine(t)
	valid := modernizrFactory + modernizrPrefixes
	one, two := "https://example.test/one", "https://example.test/two"
	for name, input := range map[string]detect.Input{
		"inline-js":         {HTML: []byte("<script>" + valid + "</script>")},
		"headers-cookies":   {Headers: http.Header{"X-Example": {valid}}, CookieNames: []string{valid}},
		"css":               {Assets: []detect.Asset{cssAsset(one, valid)}},
		"inline-css":        {InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(valid)}}},
		"empty-url":         {Assets: []detect.Asset{scriptAsset("", valid)}},
		"filename-only":     {Assets: []detect.Asset{scriptAsset("https://example.test/modernizr.min.js", "generic")}},
		"split-files":       {Assets: []detect.Asset{scriptAsset(one, modernizrFactory), scriptAsset(two, modernizrPrefixes)}},
		"same-url-parts":    {Assets: []detect.Asset{scriptAsset(one, modernizrFactory), scriptAsset(one, modernizrPrefixes)}},
		"split-kinds":       {Assets: []detect.Asset{scriptAsset(one, modernizrFactory), cssAsset(two, modernizrPrefixes)}},
		"split-page-asset":  {HTML: []byte(modernizrFactory), Assets: []detect.Asset{scriptAsset(one, modernizrPrefixes)}},
		"prefix-pair-split": {Assets: []detect.Asset{scriptAsset(one, modernizrFactory+`m._domPrefixes=p;`), scriptAsset(two, `m._cssomPrefixes=q;`)}},
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
			scriptAsset(one, valid+jqueryPrototype+jqueryExpando+lazysizesConfig+"var core="+lazysizesAPI+";"),
			scriptAsset(two, valid), scriptAsset(one, valid),
		},
	}
	got := engine.Detect(input)
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
	}
	if !reflect.DeepEqual(ids, []string{"jquery", "lazysizes", "modernizr", "nginx"}) || got[2].State != detect.Inferred || len(got[2].Evidence) != 2 || got[2].Evidence[0].AssetURL != one || got[2].Evidence[1].AssetURL != two {
		t.Fatalf("findings=%+v", got)
	}
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Fatal("unstable findings/evidence order")
	}
	got[2].Evidence[0].AssetURL = "changed"
	got[2].Evidence[0].Signals[0].Source = detect.HTML
	if again := engine.Detect(input); again[2].Evidence[0].AssetURL != one || again[2].Evidence[0].Signals[0].Source != detect.AssetJavaScript {
		t.Fatal("returned evidence mutated subsequent scans")
	}
	if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
		t.Fatalf("findings leaked into later scan: %+v", empty)
	}
}
