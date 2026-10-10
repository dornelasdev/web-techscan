package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"webscan/internal/detect"
)

// Synthetic marker scaffolds, not copied application bundles or executed code.
const nextBuildAsset = `self.__BUILD_MANIFEST={"/fixture":["private-body.js"]};self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB();`
const nextSSGAsset = `self.__SSG_MANIFEST=new Set(["/fixture"]);self.__SSG_MANIFEST_CB&&self.__SSG_MANIFEST_CB();`

func scriptAsset(url, body string) detect.Asset {
	return detect.Asset{URL: url, Source: detect.AssetJavaScript, Body: []byte(body)}
}

func TestNextManifestAssetRules(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct{ name, body, rule string }{
		{"build-object", nextBuildAsset, "asset-build-manifest"},
		{"build-iife", `self.__BUILD_MANIFEST=function(a){return {sortedPages:[a]}}("/fixture");self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB()`, "asset-build-manifest"},
		{"build-wrapped-iife", `self.__BUILD_MANIFEST=(function(){return {}})();self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB()`, "asset-build-manifest"},
		{"build-spacing", "self . __BUILD_MANIFEST = {};\n self . __BUILD_MANIFEST_CB && self . __BUILD_MANIFEST_CB ( );", "asset-build-manifest"},
		// Raw-text matching cannot distinguish copied/commented examples from
		// active code. This documented limitation must never become detected.
		{"copied-comment-remains-inferred", "/* " + nextBuildAsset + " */", "asset-build-manifest"},
		{"ssg-set", nextSSGAsset, "asset-ssg-manifest"},
		{"ssg-empty", `self.__SSG_MANIFEST=new Set;self.__SSG_MANIFEST_CB&&self.__SSG_MANIFEST_CB()`, "asset-ssg-manifest"},
		{"ssg-spacing", "self . __SSG_MANIFEST = new Set ( [] );\nself . __SSG_MANIFEST_CB && self . __SSG_MANIFEST_CB ( )", "asset-ssg-manifest"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			url := "https://example.test/renamed-script?private-token=1"
			got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, tc.body)}})
			if len(got) != 1 || got[0].ID != "nextjs" || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
				t.Fatalf("findings=%+v", got)
			}
			e := got[0].Evidence[0]
			if e.RuleID != tc.rule || e.AssetURL != url || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}) || strings.Contains(e.Description, "private-") {
				t.Fatalf("evidence=%+v", e)
			}
		})
	}
}

func TestNextAssetNearMissesAndWrongSources(t *testing.T) {
	engine := bundledEngine(t)
	for _, body := range []string{
		`__BUILD_MANIFEST __BUILD_MANIFEST_CB`,
		`self.__BUILD_MANIFEST={};`,
		`self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB()`,
		`self.__SSG_MANIFEST=new Set;`,
		`self.__SSG_MANIFEST_CB&&self.__SSG_MANIFEST_CB()`,
		`self.__BUILD_MANIFEST={};self.__SSG_MANIFEST_CB&&self.__SSG_MANIFEST_CB()`,
		strings.ReplaceAll(nextBuildAsset, "self.", "myself."),
		strings.ReplaceAll(nextBuildAsset, "self.", "object.self."),
		strings.Replace(nextBuildAsset, "__BUILD_MANIFEST=", "__BUILD_MANIFEST_EXTRA=", 1),
		strings.ReplaceAll(nextBuildAsset, "__BUILD_MANIFEST_CB", "__BUILD_MANIFEST_CB_EXTRA"),
		strings.Replace(nextBuildAsset, "={", "==={", 1),
		strings.ReplaceAll(nextBuildAsset, "__BUILD", "__build"),
		strings.ReplaceAll(nextSSGAsset, "new Set", "new SetOther"),
		`self.__BUILD_MANIFEST="generic";self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB()`,
		`self.__BUILD_MANIFEST=functionality();self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB()`,
		`self.__BUILD_MANIFEST=function$();self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB()`,
	} {
		if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}); len(got) != 0 {
			t.Errorf("body=%q got=%+v", body, got)
		}
	}
	for _, input := range []detect.Input{
		{HTML: []byte(nextBuildAsset + nextSSGAsset)},
		{Headers: http.Header{"X-Marker": {nextBuildAsset}}, CookieNames: []string{nextSSGAsset}},
		{Assets: []detect.Asset{{URL: "https://example.test/style", Source: detect.AssetCSS, Body: []byte(nextBuildAsset + nextSSGAsset)}}},
		{Assets: []detect.Asset{{URL: "https://example.test/file", Source: detect.HTML, Body: []byte(nextBuildAsset)}}},
		{Assets: []detect.Asset{scriptAsset("", nextBuildAsset)}},
		{Assets: []detect.Asset{scriptAsset("https://example.test/one", `self.__BUILD_MANIFEST={};`), scriptAsset("https://example.test/two", `self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB()`)}},
		{HTML: []byte(`self.__BUILD_MANIFEST={};`), Assets: []detect.Asset{scriptAsset("https://example.test/file", `self.__BUILD_MANIFEST_CB&&self.__BUILD_MANIFEST_CB()`)}},
		{Assets: []detect.Asset{scriptAsset("https://example.test/_next/static/_buildManifest.js", "nothing distinctive")}},
	} {
		if got := engine.Detect(input); len(got) != 0 {
			t.Errorf("wrong-source/cross-file match: %+v", got)
		}
	}
}

func TestAssetEvidenceOrderingDedupAndPageUpgrade(t *testing.T) {
	engine := bundledEngine(t)
	one, two := "https://example.test/one", "https://example.test/two"
	input := detect.Input{
		Headers: http.Header{"X-Powered-By": {"Next.js"}},
		HTML:    []byte(`<script id="__NEXT_DATA__"></script><script src="/_next/static/a.js"></script>`),
		Assets:  []detect.Asset{scriptAsset(one, nextBuildAsset+nextSSGAsset), scriptAsset(two, nextBuildAsset), scriptAsset(one, nextBuildAsset)},
	}
	got := engine.Detect(input)
	if len(got) != 1 || got[0].State != detect.Detected || len(got[0].Evidence) != 5 {
		t.Fatalf("findings=%+v", got)
	}
	var rules, urls []string
	for _, e := range got[0].Evidence {
		rules = append(rules, e.RuleID)
		urls = append(urls, e.AssetURL)
	}
	if !reflect.DeepEqual(rules, []string{"asset-build-manifest", "asset-build-manifest", "asset-ssg-manifest", "pages-html-markers", "powered-by-header"}) || !reflect.DeepEqual(urls, []string{one, two, one, "", ""}) {
		t.Fatalf("rules=%v urls=%v", rules, urls)
	}
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Error("unstable evidence ordering")
	}
	got[0].Evidence[0].AssetURL = "changed"
	got[0].Evidence[0].Signals[0].Source = "changed"
	if again := engine.Detect(input); again[0].Evidence[0].AssetURL != one || again[0].Evidence[0].Signals[0].Source != detect.AssetJavaScript {
		t.Error("evidence shared across calls")
	}
	if got := engine.Detect(detect.Input{}); len(got) != 0 {
		t.Error("engine retained asset data")
	}
}

func TestAssetRuleValidationAndCSSIsolation(t *testing.T) {
	css := `{"id":"css","state":"inferred","description":"Synthetic CSS markers","all":[{"source":"asset_css","pattern":"first-marker"},{"source":"asset_css","pattern":"second-marker"}]}`
	valid := document(technology("example", css, `"language"`) + "," + technology("language", "", ""))
	engine, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(valid)}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		input detect.Input
		want  int
	}{
		{"same-css", detect.Input{Assets: []detect.Asset{{URL: "https://example.test/style", Source: detect.AssetCSS, Body: []byte("first-marker second-marker")}}}, 2},
		{"split-css", detect.Input{Assets: []detect.Asset{{URL: "https://example.test/one", Source: detect.AssetCSS, Body: []byte("first-marker")}, {URL: "https://example.test/two", Source: detect.AssetCSS, Body: []byte("second-marker")}}}, 0},
		{"javascript", detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", "first-marker second-marker")}}, 0},
		{"html", detect.Input{HTML: []byte("first-marker second-marker")}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := engine.Detect(tc.input)
			if len(got) != tc.want {
				t.Fatalf("findings=%+v", got)
			}
			if tc.want > 0 && (got[0].Evidence[0].AssetURL == "" || got[1].Evidence[0].InferredFrom != "example" || got[1].Evidence[0].AssetURL != "") {
				t.Fatalf("bad inference provenance: %+v", got)
			}
		})
	}
	for _, source := range []string{"html", "cookie", "asset_javascript", "header"} {
		bad := strings.Replace(valid, `"source":"asset_css"`, `"source":"`+source+`"`, 1)
		if source == "header" {
			bad = strings.Replace(bad, `"source":"header"`, `"source":"header","name":"Server"`, 1)
		}
		if _, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(bad)}}); err == nil || !strings.Contains(err.Error(), "asset rules must use one asset source") {
			t.Errorf("source=%s err=%v", source, err)
		}
	}
	bad := strings.Replace(valid, `"source":"asset_css"`, `"source":"asset_css","name":"invalid"`, 1)
	if _, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(bad)}}); err == nil || !strings.Contains(err.Error(), "name is only valid") {
		t.Errorf("asset name accepted: %v", err)
	}
}
