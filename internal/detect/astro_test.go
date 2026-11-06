package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const astroGenerator = `<meta name="generator" content="Astro v5.0.0">`
const astroIsland = `<astro-island uid="example" component-url="/widget?private-component=1" renderer-url="/renderer" ssr client="load">`

func requireAstro(t *testing.T, got []detect.Finding, rules ...string) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "astro" || got[0].Name != "Astro" || got[0].Category != detect.Framework || got[0].State != detect.Inferred || len(got[0].Evidence) != len(rules) {
		t.Fatalf("findings=%+v want rules=%v", got, rules)
	}
	for i, rule := range rules {
		e := got[0].Evidence[i]
		if e.RuleID != rule || e.AssetURL != "" || e.StyleBlock != 0 || e.InferredFrom != "" || e.Description == "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.HTML}}) {
			t.Fatalf("evidence=%+v want rule=%s", e, rule)
		}
		for _, raw := range []string{"private-component", "/widget", "/renderer", "5.0.0", "7.4.5"} {
			if strings.Contains(e.Description, raw) {
				t.Errorf("raw capture data in evidence: %q", e.Description)
			}
		}
	}
}

func TestAstroGeneratorHTML(t *testing.T) {
	engine := bundledEngine(t)
	cases := map[string]string{
		"default":          astroGenerator,
		"fixture":          string(htmlFixture(t, "astro-generator.html")),
		"reversed":         `<meta content='Astro v4.16.18' name='generator'>`,
		"case-and-space":   "<META\nCONTENT = 'Astro v7.4.5'\tNAME = 'GENERATOR' />",
		"other-attributes": `<meta id="example" hidden content="Astro v5.0.0" data-label='a=b' name="generator" data-other=example>`,
		"repeated":         astroGenerator + astroGenerator,
		// Page matching is textual; it does not establish DOM activity or execution.
		"commented": "<!-- " + astroGenerator + " -->",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			requireAstro(t, engine.Detect(detect.Input{HTML: []byte(body)}), "generator-meta")
		})
	}
}

func TestAstroHydrationIslandHTML(t *testing.T) {
	engine := bundledEngine(t)
	cases := map[string]string{
		"default":              astroIsland,
		"fixture":              string(htmlFixture(t, "astro-island.html")),
		"legacy-fixture":       string(htmlFixture(t, "astro-island-legacy.html")),
		"empty-ssr":            strings.Replace(astroIsland, "ssr client", `ssr="" client`, 1),
		"single-quotes":        strings.ReplaceAll(strings.Replace(astroIsland, "ssr client", `ssr="" client`, 1), `"`, `'`),
		"case":                 strings.NewReplacer("astro-island", "ASTRO-ISLAND", "uid=", "UID=", "component-url=", "COMPONENT-URL=", "renderer-url=", "RENDERER-URL=", "ssr ", "SSR ", "client=", "CLIENT=").Replace(astroIsland),
		"other-attributes":     strings.NewReplacer(" uid=", ` class="example" uid=`, " renderer-url=", ` component-export="default" props="{}" renderer-url=`, " ssr ", " data-example='a=b'\n ssr\t ", ">", ` opts="{}">`).Replace(astroIsland),
		"absolute-custom-urls": strings.NewReplacer("/widget?private-component=1", "https://components.example.test/custom.js", "/renderer", "https://renderer.example.test/custom.js").Replace(astroIsland),
		"repeated":             astroIsland + astroIsland,
		"commented":            "<!-- " + astroIsland + " -->",
	}
	for _, client := range []string{"load", "idle", "visible", "media", "only"} {
		cases["client-"+client] = strings.Replace(astroIsland, `client="load"`, `client="`+client+`"`, 1)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			requireAstro(t, engine.Detect(detect.Input{HTML: []byte(body)}), "hydration-island-html")
		})
	}
}

func TestAstroHTMLNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	cases := map[string]string{
		"name-only":              `<meta name="generator">`,
		"content-only":           `<meta content="Astro v5.0.0">`,
		"split-meta":             `<meta name="generator"><meta content="Astro v5.0.0">`,
		"wrong-meta-tag":         strings.Replace(astroGenerator, "<meta", "<div", 1),
		"meta-tag-suffix":        strings.Replace(astroGenerator, "<meta", "<metadata", 1),
		"meta-not-closed":        strings.TrimSuffix(astroGenerator, ">"),
		"bare-product":           strings.Replace(astroGenerator, "Astro v5.0.0", "Astro", 1),
		"product-suffix":         strings.Replace(astroGenerator, "Astro v5.0.0", "Astro v5.0.0-other", 1),
		"product-case":           strings.Replace(astroGenerator, "Astro", "astro", 1),
		"short-version":          strings.Replace(astroGenerator, "5.0.0", "5.0", 1),
		"non-numeric-version":    strings.Replace(astroGenerator, "5.0.0", "development", 1),
		"unquoted-generator":     strings.Replace(astroGenerator, `"generator"`, "generator", 1),
		"prefixed-name":          strings.Replace(astroGenerator, "name=", "data-name=", 1),
		"prefixed-content":       strings.Replace(astroGenerator, "content=", "data-content=", 1),
		"meta-attribute-decoy":   `<meta data-example="name='generator' content='Astro v5.0.0'">`,
		"empty-island":           `<astro-island>`,
		"island-tag-suffix":      strings.Replace(astroIsland, "astro-island", "astro-islands", 1),
		"island-not-closed":      strings.TrimSuffix(astroIsland, ">"),
		"closing-island-only":    strings.Replace(astroIsland, "<astro-island", "</astro-island", 1),
		"false-ssr":              strings.Replace(astroIsland, "ssr client", `ssr="false" client`, 1),
		"wrong-client":           strings.Replace(astroIsland, `client="load"`, `client="future"`, 1),
		"client-case":            strings.Replace(astroIsland, `client="load"`, `client="Load"`, 1),
		"unquoted-client":        strings.Replace(astroIsland, `client="load"`, `client=load`, 1),
		"reordered-urls":         strings.Replace(astroIsland, `component-url="/widget?private-component=1" renderer-url="/renderer"`, `renderer-url="/renderer" component-url="/widget?private-component=1"`, 1),
		"split-islands":          `<astro-island uid="example" component-url="/widget"><astro-island renderer-url="/renderer" ssr client="load">`,
		"unrelated-tag-fields":   strings.Replace(astroIsland, ` renderer-url=`, `><div renderer-url=`, 1),
		"island-attribute-decoy": `<astro-island data-example="uid='example' component-url='/widget' renderer-url='/renderer' ssr client='load'">`,
		"asset-paths-only":       `<script src="/_astro/runtime.js"></script><link rel="stylesheet" href="/_astro/styles.css">`,
		"mentions-only":          `<p>Built with Astro. Astro.generator astro-island astro:hydrate</p>`,
		"escaped-generator":      strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(astroGenerator),
		"escaped-island":         strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(astroIsland),
	}
	for _, attribute := range []string{`uid="example"`, `component-url="/widget?private-component=1"`, `renderer-url="/renderer"`, "ssr", `client="load"`} {
		cases["missing-"+attribute] = strings.Replace(astroIsland, " "+attribute, "", 1)
		cases["prefixed-"+attribute] = strings.Replace(astroIsland, " "+attribute, " data-"+attribute, 1)
	}
	for _, name := range []string{"uid", "component-url", "renderer-url"} {
		var original string
		switch name {
		case "uid":
			original = `uid="example"`
		case "component-url":
			original = `component-url="/widget?private-component=1"`
		case "renderer-url":
			original = `renderer-url="/renderer"`
		}
		cases[name+"-empty"] = strings.Replace(astroIsland, original, name+`=""`, 1)
		cases[name+"-whitespace"] = strings.Replace(astroIsland, original, name+`=" "`, 1)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{HTML: []byte(body)}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestAstroSourcesEvidenceAndCoexistence(t *testing.T) {
	engine := bundledEngine(t)
	valid := astroGenerator + astroIsland
	for name, input := range map[string]detect.Input{
		"headers-cookies":         {Headers: http.Header{"X-Generator": {"Astro v5.0.0"}, "X-Example": {valid}}, CookieNames: []string{valid}},
		"javascript":              {Assets: []detect.Asset{scriptAsset("https://example.test/runtime", valid)}},
		"css":                     {Assets: []detect.Asset{cssAsset("https://example.test/styles", valid)}},
		"inline-css":              {InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(valid)}}},
		"partial-page-and-assets": {HTML: []byte(`<meta name="generator"><astro-island uid="example" component-url="/widget">`), Assets: []detect.Asset{scriptAsset("https://example.test/runtime", valid)}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(input); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
	for _, status := range []int{0, 200, 403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			input := detect.Input{HTTPStatus: status, HTML: []byte(astroIsland + astroGenerator + valid)}
			requireAstro(t, engine.Detect(input), "generator-meta", "hydration-island-html")
			got := engine.Detect(input)
			got[0].Evidence[0].Signals[0].Source = detect.Header
			requireAstro(t, engine.Detect(input), "generator-meta", "hydration-island-html")
			if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
				t.Fatalf("retained findings=%+v", empty)
			}
		})
	}
	input := detect.Input{HTML: []byte(valid), Headers: http.Header{"Server": {"nginx"}}, Assets: []detect.Asset{scriptAsset("https://example.test/runtime", jqueryPrototype+jqueryExpando+reactClientAssignment+reactElementSymbol)}}
	got := engine.Detect(input)
	var ids []string
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	if !reflect.DeepEqual(ids, []string{"astro", "jquery", "nginx", "react"}) || got[0].State != detect.Inferred || got[2].State != detect.Detected {
		t.Fatalf("findings=%+v", got)
	}
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Fatal("unstable evidence")
	}
}
