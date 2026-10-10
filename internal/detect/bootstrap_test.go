package detect_test

import (
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

// Minimal authored scaffolds, not a full stylesheet or evidence of runtime use.
const bootstrapBanner = `/*! Bootstrap v5.3.3 (https://getbootstrap.com/) */`
const bootstrapButtons = `.btn{--bs-btn-padding-x:.75rem;--bs-btn-padding-y:.375rem;padding:var(--bs-btn-padding-y) var(--bs-btn-padding-x)}`

func cssAsset(url, body string) detect.Asset {
	return detect.Asset{URL: url, Source: detect.AssetCSS, Body: []byte(body)}
}

func TestBootstrapCSSRules(t *testing.T) {
	engine := bundledEngine(t)
	cases := map[string]string{
		"compact":            bootstrapBanner + bootstrapButtons,
		"spacing":            bootstrapBanner + "\n.btn\t{\n --bs-btn-padding-x : 2rem;\n padding : var( --bs-btn-padding-y )\tvar( --bs-btn-padding-x ) ;\n}",
		"custom-value":       bootstrapBanner + strings.Replace(bootstrapButtons, ".75rem", "var(--custom-space)", 1),
		"other-declarations": bootstrapBanner + strings.Replace(bootstrapButtons, ".btn{", ".btn{display:inline-block;", 1),
		"nested-media":       bootstrapBanner + "@media screen{" + bootstrapButtons + "}",
		// Raw text is not CSS parsing. Copied/commented component text can
		// still match and must remain inferred, never proof of applied styles.
		"commented-component": bootstrapBanner + "/* example {}" + bootstrapButtons + " */",
	}
	for _, name := range []string{"bootstrap-5.2.css", "bootstrap-5.3.min.css"} {
		body, err := os.ReadFile("testdata/coverage/" + name)
		if err != nil {
			t.Fatal(err)
		}
		cases[name] = string(body)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			url := "https://example.test/renamed?private-token=1"
			got := engine.Detect(detect.Input{Assets: []detect.Asset{cssAsset(url, body)}})
			if len(got) != 1 || got[0].ID != "bootstrap" || got[0].Name != "Bootstrap" || got[0].Category != detect.UIFramework || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
				t.Fatalf("findings=%+v", got)
			}
			e := got[0].Evidence[0]
			if e.RuleID != "asset-css-banner-and-buttons" || e.AssetURL != url || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetCSS}, {Source: detect.AssetCSS}}) {
				t.Fatalf("evidence=%+v", e)
			}
			if strings.Contains(e.Description, ".75rem") || strings.Contains(e.Description, "private-") {
				t.Errorf("raw CSS/URL data in description: %q", e.Description)
			}
		})
	}
}

func TestBootstrapCSSNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	valid := bootstrapBanner + bootstrapButtons
	cases := map[string]string{
		"empty":                     "",
		"banner-only":               bootstrapBanner,
		"buttons-only":              bootstrapButtons,
		"generic-classes":           bootstrapBanner + `.btn{padding:1rem}.container{display:block}`,
		"bare-prefix":               bootstrapBanner + `:root{--bs-color:red}`,
		"banner-lookalike":          strings.Replace(valid, "Bootstrap v", "Bootstrapish v", 1),
		"banner-wrong-case":         strings.Replace(valid, "Bootstrap", "bootstrap", 1),
		"unreviewed-old-version":    strings.Replace(valid, "v5.3.3", "v5.1.3", 1),
		"unreviewed-future-version": strings.Replace(valid, "v5.3.3", "v6.0.0", 1),
		"prerelease":                strings.Replace(valid, "v5.3.3", "v5.3.3-beta1", 1),
		"url-lookalike":             strings.Replace(valid, "getbootstrap.com/", "getbootstrap.com.evil/", 1),
		"not-a-banner":              strings.Replace(valid, "/*!", "", 1),
		"unclosed-banner":           strings.Replace(valid, "*/", "", 1),
		"selector-prefix":           strings.Replace(valid, ".btn{", ".mybtn{", 1),
		"selector-suffix":           strings.Replace(valid, ".btn{", ".btn-other{", 1),
		"compound-selector":         strings.Replace(valid, ".btn{", ".other.btn{", 1),
		"descendant-selector":       strings.Replace(valid, ".btn{", ".other .btn{", 1),
		"variable-prefix":           strings.ReplaceAll(valid, "--bs-", "--custom-bs-"),
		"variable-suffix":           strings.ReplaceAll(valid, "--bs-btn-padding-x", "--bs-btn-padding-x-other"),
		"variable-case":             strings.ReplaceAll(valid, "--bs-btn-", "--BS-btn-"),
		"missing-declaration":       strings.Replace(valid, "--bs-btn-padding-x:.75rem;", "", 1),
		"empty-declaration":         strings.Replace(valid, ":.75rem;", ": ;", 1),
		"missing-usage":             strings.Replace(valid, "padding:var(--bs-btn-padding-y) var(--bs-btn-padding-x)", "", 1),
		"wrong-property":            strings.Replace(valid, ";padding:", ";custom-padding:", 1),
		"wrong-function":            strings.ReplaceAll(valid, "var(", "myvar("),
		"split-blocks":              bootstrapBanner + `.btn{--bs-btn-padding-x:.75rem}.btn{padding:var(--bs-btn-padding-y) var(--bs-btn-padding-x)}`,
		"unclosed-block":            strings.TrimSuffix(valid, "}"),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{cssAsset("https://example.test/bootstrap.css", body)}}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestBootstrapCSSSourceIsolation(t *testing.T) {
	engine := bundledEngine(t)
	valid := bootstrapBanner + bootstrapButtons
	for name, input := range map[string]detect.Input{
		"html":                {HTML: []byte("<style>" + valid + "</style>")},
		"headers-and-cookies": {Headers: http.Header{"X-Marker": {valid}}, CookieNames: []string{valid}},
		"javascript":          {Assets: []detect.Asset{scriptAsset("https://example.test/file", valid)}},
		"empty-url":           {Assets: []detect.Asset{cssAsset("", valid)}},
		"split-files":         {Assets: []detect.Asset{cssAsset("https://example.test/one", bootstrapBanner), cssAsset("https://example.test/two", bootstrapButtons)}},
		"split-source":        {Assets: []detect.Asset{scriptAsset("https://example.test/one", bootstrapBanner), cssAsset("https://example.test/two", bootstrapButtons)}},
		"split-page-asset":    {HTML: []byte(bootstrapBanner), Assets: []detect.Asset{cssAsset("https://example.test/file", bootstrapButtons)}},
		"filename-only":       {Assets: []detect.Asset{cssAsset("https://example.test/bootstrap.min.css", ".btn{}")}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(input); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestBootstrapCSSEvidenceDeduplication(t *testing.T) {
	engine := bundledEngine(t)
	one, two := "https://example.test/one", "https://example.test/two"
	body := bootstrapBanner + bootstrapButtons
	input := detect.Input{Assets: []detect.Asset{cssAsset(one, body+body), cssAsset(two, body), cssAsset(one, body)}}
	got := engine.Detect(input)
	if len(got) != 1 || len(got[0].Evidence) != 2 || got[0].Evidence[0].AssetURL != one || got[0].Evidence[1].AssetURL != two {
		t.Fatalf("findings=%+v", got)
	}
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Error("unstable evidence")
	}
	if got := engine.Detect(detect.Input{}); len(got) != 0 {
		t.Fatal("retained asset evidence across scans")
	}
}
