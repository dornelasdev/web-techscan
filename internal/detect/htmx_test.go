package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const htmxLegacyHeaders = `{"HX-Request":"true","HX-Trigger":a(e,"id"),"HX-Trigger-Name":a(e,"name"),"HX-Target":b(t,"id"),"HX-Current-URL":location.href}`
const htmxLegacyLookup = `d().querySelector('meta[name="htmx-config"]');`
const htmxV4Headers = `{"HX-Request":"true","HX-Source":this.#x(e),"HX-Current-URL":location.href,Accept:"text/html"}`
const htmxV4Lookup = `document.querySelector('meta[name="htmx-config"]');`

type htmxEvidence struct{ rule, url string }

func requireHtmx(t *testing.T, got []detect.Finding, want ...htmxEvidence) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "htmx" || got[0].Name != "htmx" || got[0].Category != detect.JSLibrary || got[0].State != detect.Inferred || len(got[0].Evidence) != len(want) {
		t.Fatalf("findings=%+v want=%v", got, want)
	}
	for i, expected := range want {
		e := got[0].Evidence[i]
		if e.RuleID != expected.rule || e.AssetURL != expected.url || e.StyleBlock != 0 || e.InferredFrom != "" || e.Description == "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}) {
			t.Fatalf("evidence=%+v want=%+v", e, expected)
		}
		for _, raw := range []string{"private-", "HX-Request", "htmx-config", "1.9.12", "2.0.11", "4.0.1"} {
			if strings.Contains(e.Description, raw) {
				t.Errorf("raw source data in description: %s", e.Description)
			}
		}
	}
}

func TestHtmxRuntimeAssets(t *testing.T) {
	engine := bundledEngine(t)
	legacy := "var headers=" + htmxLegacyHeaders + ";" + htmxLegacyLookup
	v4 := "var headers=" + htmxV4Headers + ";" + htmxV4Lookup
	for _, family := range []struct{ name, rule, body string }{
		{"v1-v2", "asset-v1-v2-core-runtime", legacy},
		{"v4", "asset-v4-core-runtime", v4},
	} {
		t.Run(family.name, func(t *testing.T) {
			cases := map[string]string{
				"compact":          family.body,
				"readable-fixture": string(htmlFixture(t, "htmx-"+family.name+"-core.js")),
				"compact-fixture":  string(htmlFixture(t, "htmx-"+family.name+"-core.min.js")),
				"trailing-comma":   strings.Replace(family.body, "}", ",}", 1),
				"renamed":          strings.NewReplacer("a(e,", "$attribute($element,", "b(t,", "$target($other,", "d()", "$document()", ".#x(e)", ".#$identifier($element)").Replace(family.body),
				"spaced":           strings.NewReplacer(":", " : ", ",", " , ", "querySelector(", "querySelector ( ", ".href", " . href").Replace(family.body),
				"esm-shaped":       "export function headers(){return " + strings.SplitN(strings.TrimPrefix(family.body, "var headers="), ";", 2)[0] + ";}" + strings.SplitN(family.body, ";", 2)[1],
				"repeated":         family.body + family.body,
				"nested-headers":   "var container={headers:" + strings.SplitN(strings.TrimPrefix(family.body, "var headers="), ";", 2)[0] + "};" + strings.SplitN(family.body, ";", 2)[1],
				// These are textual structures, without ownership/scope or execution proof.
				"commented": "/* " + family.body + " */",
			}
			if family.name == "v1-v2" {
				cases["v1-document-helper"] = strings.Replace(legacy, "location.href", "$root().location.href", 1)
				cases["reversed-groups"] = htmxLegacyLookup + "var headers=" + htmxLegacyHeaders + ";"
				cases["single-quoted-headers"] = strings.ReplaceAll(htmxLegacyHeaders, `"`, `'`) + ";" + htmxLegacyLookup
			} else {
				cases["quoted-accept"] = strings.Replace(v4, "Accept:", `"Accept":`, 1)
				cases["single-quoted-headers"] = strings.ReplaceAll(htmxV4Headers, `"`, `'`) + ";" + htmxV4Lookup
				cases["reversed-groups"] = htmxV4Lookup + "var headers=" + htmxV4Headers + ";"
			}
			cases["selector-other-quotes"] = strings.Replace(family.body, `'meta[name="htmx-config"]'`, `"meta[name='htmx-config']"`, 1)
			url := "https://example.test/renamed?private-token=1"
			for name, body := range cases {
				t.Run(name, func(t *testing.T) {
					requireHtmx(t, engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, body)}}), htmxEvidence{family.rule, url})
				})
			}
		})
	}
}

func TestHtmxRuntimeNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	for _, family := range []struct{ name, headers, lookup string }{
		{"v1-v2", htmxLegacyHeaders, htmxLegacyLookup},
		{"v4", htmxV4Headers, htmxV4Lookup},
	} {
		t.Run(family.name, func(t *testing.T) {
			valid := "var headers=" + family.headers + ";" + family.lookup
			cases := map[string]string{
				"headers-only":         family.headers,
				"lookup-only":          family.lookup,
				"banner":               `/*! htmx 4.0.1 */`,
				"boolean-request":      strings.Replace(valid, `"HX-Request":"true"`, `"HX-Request":true`, 1),
				"wrong-request":        strings.Replace(valid, `"HX-Request":"true"`, `"HX-Request":"false"`, 1),
				"header-case":          strings.Replace(valid, "HX-Request", "hx-request", 1),
				"header-suffix":        strings.Replace(valid, "HX-Request", "HX-Request-Other", 1),
				"missing-first":        strings.Replace(valid, `"HX-Request":"true",`, "", 1),
				"extra-first":          strings.Replace(valid, "{", `{other:1,`, 1),
				"extra-last":           strings.Replace(valid, "}", `,other:1}`, 1),
				"nested-request-value": strings.Replace(valid, `"HX-Request":"true"`, `"HX-Request":{value:"true"}`, 1),
				"incomplete-object":    strings.Replace(valid, "}", "", 1),
				"header-comment":       strings.Replace(valid, `"true",`, `"true",/* gap */`, 1),
				"computed-url":         strings.Replace(valid, "location.href", "location.href+suffix", 1),
				"qualified-location":   strings.Replace(valid, "location.href", "window.location.href", 1),
				"wrong-query-method":   strings.Replace(valid, ".querySelector(", ".querySelectorAll(", 1),
				"wrong-selector":       strings.Replace(valid, "htmx-config", "htmx-config-other", 1),
				"selector-prefix":      strings.Replace(valid, "meta[name=", "head meta[name=", 1),
				"meta-markup-only":     family.headers + `;var markup='<meta name="htmx-config">';`,
				"consumer-request":     `request.setRequestHeader("HX-Request","true");` + family.lookup,
				"directive-usage":      `<button hx-get="/example" hx-target="#target" hx-swap="outerHTML">Example</button>`,
				"data-directives":      `<button data-hx-post="/example" data-hx-swap="outerHTML">Example</button>`,
				"ordinary-api":         `htmx.ajax("GET","/example");htmx.on("htmx:load",ready);`,
			}
			if family.name == "v1-v2" {
				cases["missing-trigger"] = strings.Replace(valid, `"HX-Trigger":a(e,"id"),`, "", 1)
				cases["wrong-trigger-attribute"] = strings.Replace(valid, `a(e,"id")`, `a(e,"name")`, 1)
				cases["extra-call-argument"] = strings.Replace(valid, `a(e,"id")`, `a(e,"id",other)`, 1)
				cases["reordered-fields"] = strings.Replace(valid, `"HX-Trigger":a(e,"id"),"HX-Trigger-Name":a(e,"name")`, `"HX-Trigger-Name":a(e,"name"),"HX-Trigger":a(e,"id")`, 1)
				cases["split-objects"] = strings.Replace(valid, `"HX-Target":`, `};var other={"HX-Target":`, 1)
				cases["helper-arguments"] = strings.Replace(valid, "d()", "d(other)", 1)
				cases["qualified-helper"] = strings.Replace(valid, "d()", "global.d()", 1)
				cases["v4-lookup"] = family.headers + ";" + htmxV4Lookup
			} else {
				cases["missing-source"] = strings.Replace(valid, `"HX-Source":this.#x(e),`, "", 1)
				cases["non-private-method"] = strings.Replace(valid, "this.#x(e)", "this.x(e)", 1)
				cases["wrong-receiver"] = strings.Replace(valid, "this.#x(e)", "other.#x(e)", 1)
				cases["extra-source-argument"] = strings.Replace(valid, "this.#x(e)", "this.#x(e,other)", 1)
				cases["missing-accept"] = strings.Replace(valid, `,Accept:"text/html"`, "", 1)
				cases["accept-case"] = strings.Replace(valid, "Accept:", "accept:", 1)
				cases["wrong-accept"] = strings.Replace(valid, "text/html", "application/json", 1)
				cases["source-url-reordered"] = strings.Replace(valid, `"HX-Source":this.#x(e),"HX-Current-URL":location.href`, `"HX-Current-URL":location.href,"HX-Source":this.#x(e)`, 1)
				cases["split-objects"] = strings.Replace(valid, `"HX-Current-URL":`, `};var other={"HX-Current-URL":`, 1)
				cases["qualified-document"] = strings.Replace(valid, "document.querySelector", "window.document.querySelector", 1)
				cases["legacy-lookup"] = family.headers + ";" + htmxLegacyLookup
			}
			for name, body := range cases {
				t.Run(name, func(t *testing.T) {
					if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}); len(got) != 0 {
						t.Fatalf("findings=%+v", got)
					}
				})
			}
		})
	}
}

func TestHtmxIsolationAndCombinedEvidence(t *testing.T) {
	engine := bundledEngine(t)
	legacy := htmxLegacyHeaders + ";" + htmxLegacyLookup
	v4 := htmxV4Headers + ";" + htmxV4Lookup
	one, two, three := "https://example.test/one?private-token=1", "https://example.test/two", "https://example.test/three"
	for _, body := range []string{legacy, v4} {
		for name, input := range map[string]detect.Input{
			"html":            {HTML: []byte("<script>" + body + "</script>")},
			"headers-cookies": {Headers: http.Header{"HX-Request": {"true"}, "X-Example": {body}}, CookieNames: []string{body}},
			"css":             {Assets: []detect.Asset{cssAsset(one, body)}},
			"inline-css":      {InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(body)}}},
			"empty-url":       {Assets: []detect.Asset{scriptAsset("", body)}},
			"filename":        {Assets: []detect.Asset{scriptAsset("https://example.test/htmx.min.js", "generic")}},
		} {
			t.Run(name, func(t *testing.T) {
				if got := engine.Detect(input); len(got) != 0 {
					t.Fatalf("findings=%+v", got)
				}
			})
		}
	}
	for _, family := range []struct{ headers, lookup string }{{htmxLegacyHeaders, htmxLegacyLookup}, {htmxV4Headers, htmxV4Lookup}} {
		for name, input := range map[string]detect.Input{
			"split-files":      {Assets: []detect.Asset{scriptAsset(one, family.headers), scriptAsset(two, family.lookup)}},
			"same-url-parts":   {Assets: []detect.Asset{scriptAsset(one, family.headers), scriptAsset(one, family.lookup)}},
			"split-kinds":      {Assets: []detect.Asset{scriptAsset(one, family.headers), cssAsset(two, family.lookup)}},
			"split-page-asset": {HTML: []byte(family.lookup), Assets: []detect.Asset{scriptAsset(one, family.headers)}},
		} {
			t.Run(name, func(t *testing.T) {
				if got := engine.Detect(input); len(got) != 0 {
					t.Fatalf("findings=%+v", got)
				}
			})
		}
	}
	input := detect.Input{Assets: []detect.Asset{scriptAsset(one, legacy), scriptAsset(two, v4), scriptAsset(three, legacy+v4), scriptAsset(one, legacy)}}
	want := []htmxEvidence{{"asset-v1-v2-core-runtime", one}, {"asset-v1-v2-core-runtime", three}, {"asset-v4-core-runtime", two}, {"asset-v4-core-runtime", three}}
	requireHtmx(t, engine.Detect(input), want...)
	got := engine.Detect(input)
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Fatal("unstable evidence order")
	}
	got[0].Evidence[0].AssetURL = "changed"
	got[0].Evidence[0].Signals[0].Source = detect.HTML
	requireHtmx(t, engine.Detect(input), want...)
	if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
		t.Fatalf("retained findings=%+v", empty)
	}
	input.HTML = []byte(astroGenerator)
	input.Headers = http.Header{"Server": {"nginx"}}
	input.Assets[0].Body = []byte(legacy + alpineEvents + "var core=" + alpineAPI + ";" + jqueryPrototype + jqueryExpando)
	got = engine.Detect(input)
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
	}
	if !reflect.DeepEqual(ids, []string{"alpinejs", "astro", "htmx", "jquery", "nginx"}) || got[2].State != detect.Inferred || got[4].State != detect.Detected {
		t.Fatalf("mixed findings=%+v", got)
	}
}
