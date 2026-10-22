package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

// Authored marker scaffolds, not complete stylesheets or proof of applied styles.
const tailwind3Banner = `/*! tailwindcss v3.4.17 | MIT License | https://tailwindcss.com */`
const tailwind3Preflight = `::before,::after{--tw-content:'';}`
const tailwind4Banner = `/*! tailwindcss v4.1.0 | MIT License | https://tailwindcss.com */`
const tailwind4Property = `@property --tw-translate-x{syntax:"*";inherits:false;initial-value:0}`
const tailwind4Translate = `.sample{--tw-translate-x:100%;translate:var(--tw-translate-x) var(--tw-translate-y)}`

func requireTailwind(t *testing.T, got []detect.Finding, rules, urls []string) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "tailwindcss" || got[0].Name != "Tailwind CSS" || got[0].Category != detect.UIFramework || got[0].State != detect.Inferred || len(got[0].Evidence) != len(rules) {
		t.Fatalf("findings=%+v", got)
	}
	for i, e := range got[0].Evidence {
		count := 2
		if rules[i] == "asset-css-v4-banner-and-translate" {
			count = 3
		}
		signals := make([]detect.Signal, count)
		for j := range signals {
			signals[j].Source = detect.AssetCSS
		}
		if e.RuleID != rules[i] || e.AssetURL != urls[i] || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, signals) {
			t.Fatalf("evidence=%+v", e)
		}
	}
}

func TestTailwindCSSRules(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct{ name, rule, body string }{
		{"v3-readable-fixture", "asset-css-v3-banner-and-preflight", string(htmlFixture(t, "tailwind-3.4.css"))},
		{"v3-compact-reordered", "asset-css-v3-banner-and-preflight", tailwind3Banner + `:after,:before{--tw-content:""}`},
		{"v3-mixed-colons", "asset-css-v3-banner-and-preflight", tailwind3Banner + `:before,::after{--tw-content:''}`},
		{"v3-spacing", "asset-css-v3-banner-and-preflight", tailwind3Banner + "\n::before,\n::after\t{\n--tw-content : \"\" ;\n}"},
		{"v4-compact-fixture", "asset-css-v4-banner-and-translate", string(htmlFixture(t, "tailwind-4.1.min.css"))},
		{"v4-spacing", "asset-css-v4-banner-and-translate", tailwind4Banner + "\n@property --tw-translate-x {\n syntax : '*';\n inherits : false;\n initial-value : 0;\n}\n.custom {\n --tw-translate-x : var(--custom);\n color:red;\n translate : var( --tw-translate-x )\tvar( --tw-translate-y );\n}"},
		{"v4-nested", "asset-css-v4-banner-and-translate", tailwind4Banner + "@layer utilities{" + tailwind4Translate + "}" + tailwind4Property},
		// Raw matching is not a CSS parser; copied/commented rules remain inferred.
		{"v4-commented", "asset-css-v4-banner-and-translate", tailwind4Banner + "/* {}" + tailwind4Property + tailwind4Translate + " */"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, status := range []int{0, 200, 403} {
				url := "https://example.test/renamed?private-token=1"
				input := detect.Input{HTTPStatus: status, Assets: []detect.Asset{cssAsset(url, tc.body)}}
				got := engine.Detect(input)
				requireTailwind(t, got, []string{tc.rule}, []string{url})
				if !reflect.DeepEqual(got, engine.Detect(input)) {
					t.Fatal("unstable repeat scan")
				}
				got[0].Evidence[0].Signals[0].Source = detect.HTML
				requireTailwind(t, engine.Detect(input), []string{tc.rule}, []string{url})
			}
			if got := engine.Detect(detect.Input{}); len(got) != 0 {
				t.Fatalf("retained evidence: %+v", got)
			}
		})
	}
}

func TestTailwindCSSPartialAndNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	for _, parts := range [][]string{{tailwind3Banner, tailwind3Preflight}, {tailwind4Banner, tailwind4Property, tailwind4Translate}} {
		for mask := 0; mask < (1<<len(parts))-1; mask++ {
			var body string
			for i, part := range parts {
				if mask&(1<<i) != 0 {
					body += part
				}
			}
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{cssAsset("https://example.test/file", body)}}); len(got) != 0 {
				t.Fatalf("partial mask=%d findings=%+v", mask, got)
			}
		}
	}
	v3 := tailwind3Banner + tailwind3Preflight
	v4 := tailwind4Banner + tailwind4Property + tailwind4Translate
	cases := map[string]string{
		"generic-utilities":          `.flex{display:flex}.text-center{text-align:center}:root{--tw-color:red}`,
		"v3-wrong-family":            strings.Replace(v3, "v3.4.17", "v3.3.7", 1),
		"v4-wrong-family":            strings.Replace(v4, "v4.1.0", "v4.0.0", 1),
		"v3-banner-v4-markers":       tailwind3Banner + tailwind4Property + tailwind4Translate,
		"v4-banner-v3-markers":       tailwind4Banner + tailwind3Preflight,
		"v3-prerelease":              strings.Replace(v3, "v3.4.17", "v3.4.17-beta.1", 1),
		"v4-prerelease":              strings.Replace(v4, "v4.1.0", "v4.1.0-beta.1", 1),
		"v3-nonempty-content":        strings.Replace(v3, "''", "'x'", 1),
		"v3-split-selectors":         tailwind3Banner + `::before{--tw-content:''}::after{--tw-content:''}`,
		"v3-extra-selector":          strings.Replace(v3, "::before", ".custom,::before", 1),
		"v3-unclosed-block":          strings.TrimSuffix(v3, "}"),
		"v4-registration-suffix":     strings.Replace(v4, "@property --tw-translate-x", "@property --tw-translate-x-other", 1),
		"v4-registration-type":       strings.Replace(v4, `syntax:"*"`, `syntax:"<length>"`, 1),
		"v4-registration-inherits":   strings.Replace(v4, "inherits:false", "inherits:true", 1),
		"v4-registration-default":    strings.Replace(v4, "initial-value:0", "initial-value:1", 1),
		"v4-registration-split":      tailwind4Banner + `@property --tw-translate-x{syntax:"*";inherits:false}a{initial-value:0}` + tailwind4Translate,
		"v4-declaration-suffix":      strings.Replace(v4, "--tw-translate-x:100%", "--tw-translate-x-other:100%", 1),
		"v4-empty-declaration":       strings.Replace(v4, ":100%;", ": ;", 1),
		"v4-usage-property":          strings.Replace(v4, ";translate:", ";custom-translate:", 1),
		"v4-usage-function":          strings.ReplaceAll(v4, "var(", "myvar("),
		"v4-usage-suffix":            strings.Replace(v4, "var(--tw-translate-y)", "var(--tw-translate-y-other)", 1),
		"v4-usage-extra-value":       strings.Replace(v4, "var(--tw-translate-y)", "var(--tw-translate-y) 1px", 1),
		"v4-declaration-usage-split": tailwind4Banner + tailwind4Property + `.a{--tw-translate-x:100%}.b{translate:var(--tw-translate-x) var(--tw-translate-y)}`,
		"v4-unclosed-usage":          strings.TrimSuffix(v4, "}"),
		"v4-unclosed-registration":   tailwind4Banner + strings.TrimSuffix(tailwind4Property, "}") + tailwind4Translate,
	}
	for name, valid := range map[string]string{"v3": v3, "v4": v4} {
		for label, body := range map[string]string{
			"banner-case":      strings.Replace(valid, "tailwindcss v", "TailwindCSS v", 1),
			"banner-lookalike": strings.Replace(valid, "tailwindcss v", "not-tailwindcss v", 1),
			"banner-url":       strings.Replace(valid, "tailwindcss.com", "tailwindcss.com.evil", 1),
			"banner-license":   strings.Replace(valid, "MIT License", "Other License", 1),
			"unclosed-banner":  strings.Replace(valid, "*/", "", 1),
			"not-banner":       strings.Replace(valid, "/*!", "/*", 1),
			"variable-prefix":  strings.ReplaceAll(valid, "--tw-", "--custom-tw-"),
			"variable-case":    strings.ReplaceAll(valid, "--tw-", "--TW-"),
		} {
			cases[name+"/"+label] = body
		}
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{cssAsset("https://example.test/tailwind.css", body)}}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestTailwindCSSIsolation(t *testing.T) {
	engine := bundledEngine(t)
	for _, parts := range [][]string{{tailwind3Banner, tailwind3Preflight}, {tailwind4Banner, tailwind4Property, tailwind4Translate}} {
		valid := strings.Join(parts, "")
		cases := map[string]detect.Input{
			"inline":          {HTML: []byte("<style>" + valid + "</style>")},
			"headers-cookies": {Headers: http.Header{"Server": {valid}, "X-Powered-By": {valid}}, CookieNames: []string{valid}},
			"javascript":      {Assets: []detect.Asset{scriptAsset("https://example.test/file", valid)}},
			"empty-url":       {Assets: []detect.Asset{cssAsset("", valid)}},
			"filename":        {Assets: []detect.Asset{cssAsset("https://example.test/tailwind.min.css", ".flex{display:flex}")}},
		}
		// Every nonempty partition across bodies must remain incomplete, even
		// with an identical URL or a different source/page holding the rest.
		for mask := 1; mask < (1<<len(parts))-1; mask++ {
			var left, right string
			for i, part := range parts {
				if mask&(1<<i) != 0 {
					left += part
				} else {
					right += part
				}
			}
			cases["split-files-"+string(rune('0'+mask))] = detect.Input{Assets: []detect.Asset{cssAsset("https://example.test/one", left), cssAsset("https://example.test/two", right)}}
			cases["split-same-url-"+string(rune('0'+mask))] = detect.Input{Assets: []detect.Asset{cssAsset("https://example.test/file", left), cssAsset("https://example.test/file", right)}}
			cases["split-js-css-"+string(rune('0'+mask))] = detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/one", left), cssAsset("https://example.test/two", right)}}
			cases["split-page-css-"+string(rune('0'+mask))] = detect.Input{HTML: []byte(left), Assets: []detect.Asset{cssAsset("https://example.test/file", right)}}
		}
		for name, input := range cases {
			t.Run(name+"/"+parts[0], func(t *testing.T) {
				if got := engine.Detect(input); len(got) != 0 {
					t.Fatalf("findings=%+v", got)
				}
			})
		}
	}
}

func TestTailwindCSSEvidenceAndIndependentBootstrap(t *testing.T) {
	engine := bundledEngine(t)
	v3, v4 := tailwind3Banner+tailwind3Preflight, tailwind4Banner+tailwind4Property+tailwind4Translate
	one, two := "https://example.test/one", "https://example.test/two"
	input := detect.Input{Assets: []detect.Asset{cssAsset(two, v4+v4), cssAsset(one, v3+v4), cssAsset(two, v4)}}
	got := engine.Detect(input)
	requireTailwind(t, got, []string{"asset-css-v3-banner-and-preflight", "asset-css-v4-banner-and-translate", "asset-css-v4-banner-and-translate"}, []string{one, two, one})
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Fatal("unstable evidence")
	}
	input.Headers = http.Header{"Server": {"nginx"}}
	input.Assets[1].Body = []byte(v3 + v4 + bootstrapBanner + bootstrapButtons)
	got = engine.Detect(input)
	var ids []string
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	if !reflect.DeepEqual(ids, []string{"bootstrap", "nginx", "tailwindcss"}) {
		t.Fatalf("findings=%+v", got)
	}
	// Mutating a returned evidence record must not affect a later result.
	got[2].Evidence[0].Description = "changed"
	if engine.Detect(input)[2].Evidence[0].Description == "changed" {
		t.Fatal("retained mutated evidence")
	}
}
