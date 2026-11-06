package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const alpineEvents = `a(document,"alpine:init"),a(document,"alpine:initializing");`
const alpineAPI = `{flushAndStopDeferringMutations:b,dontAutoEvaluateFunctions:c,disableEffectScheduling:d,startObservingMutations:e,stopObservingMutations:f,setReactivityEngine:g}`
const alpineShorthand = `{flushAndStopDeferringMutations,dontAutoEvaluateFunctions,disableEffectScheduling,startObservingMutations,stopObservingMutations,setReactivityEngine}`

func requireAlpine(t *testing.T, got []detect.Finding, urls ...string) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "alpinejs" || got[0].Name != "Alpine.js" || got[0].Category != detect.JSFramework || got[0].State != detect.Inferred || len(got[0].Evidence) != len(urls) {
		t.Fatalf("findings=%+v want URLs=%v", got, urls)
	}
	for i, url := range urls {
		e := got[0].Evidence[i]
		if e.RuleID != "asset-core-runtime" || e.AssetURL != url || e.StyleBlock != 0 || e.InferredFrom != "" || e.Description == "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}) {
			t.Fatalf("evidence=%+v want URL=%s", e, url)
		}
		for _, raw := range []string{"private-", "alpine:init", "flushAndStopDeferringMutations", "3.14.9", "3.17.5"} {
			if strings.Contains(e.Description, raw) {
				t.Errorf("raw source data in description: %q", e.Description)
			}
		}
	}
}

func TestAlpineCoreRuntime(t *testing.T) {
	engine := bundledEngine(t)
	valid := alpineEvents + "var core=" + alpineAPI + ";"
	cases := map[string]string{
		"mapped":              valid,
		"shorthand":           alpineEvents + "var core=" + alpineShorthand + ";",
		"mixed-members":       strings.Replace(valid, "dontAutoEvaluateFunctions:c", "dontAutoEvaluateFunctions", 1),
		"single-quotes":       strings.ReplaceAll(valid, `"`, `'`),
		"statement-separator": strings.Replace(valid, `"alpine:init"),a(`, `"alpine:init");a(`, 1),
		"renamed-spaced":      "$emit ( document , 'alpine:init' );\n$emit ( document , 'alpine:initializing' );\nvar core = { flushAndStopDeferringMutations : $flush , dontAutoEvaluateFunctions : $dont , disableEffectScheduling : $disable , startObservingMutations : $start , stopObservingMutations : $stop , setReactivityEngine : $reactivity };",
		"other-members":       alpineEvents + `var core={version:"custom",` + strings.TrimPrefix(alpineAPI, "{") + ";",
		"trailing-member":     strings.Replace(valid, "setReactivityEngine:g}", "setReactivityEngine:g,other:h}", 1),
		"trailing-comma":      strings.Replace(valid, "setReactivityEngine:g}", "setReactivityEngine:g,}", 1),
		"reverse-groups":      "var core=" + alpineAPI + ";" + alpineEvents,
		"repeated":            valid + valid,
		// This is textual matching, not proof of scope, identifier equality or execution.
		"different-call-identifiers": strings.Replace(valid, `),a(document,"alpine:initializing")`, `),other(document,"alpine:initializing")`, 1),
		"commented":                  "/* " + valid + " */",
	}
	for _, name := range []string{"alpine-core.js", "alpine-core.min.js", "alpine-core.esm.js"} {
		cases[name] = string(htmlFixture(t, name))
	}
	url := "https://example.test/renamed?private-token=1"
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			requireAlpine(t, engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, body)}}), url)
		})
	}
}

func TestAlpineRuntimeNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	valid := alpineEvents + "var core=" + alpineAPI + ";"
	cases := map[string]string{
		"empty":                 "",
		"events-only":           alpineEvents,
		"api-only":              "var core=" + alpineAPI + ";",
		"banner-version":        `/*! Alpine.js 3.17.5 */ var options={version:"3.17.5"};`,
		"consumer-listeners":    `document.addEventListener("alpine:init",setup);document.addEventListener("alpine:initializing",ready);` + "var core=" + alpineAPI + ";",
		"consumer-api":          `window.Alpine=Alpine;Alpine.start();Alpine.data("example",()=>({}));`,
		"directives":            `<div x-data="{}" x-init="setup()" x-show="visible"></div>`,
		"wrong-first-event":     strings.Replace(valid, "alpine:init", "alpine:initialized", 1),
		"event-suffix":          strings.Replace(valid, `"alpine:init"`, `"alpine:init-other"`, 1),
		"event-case":            strings.Replace(valid, "alpine:init", "Alpine:init", 1),
		"reversed-events":       strings.NewReplacer("alpine:init\"", "alpine:initializing\"", "alpine:initializing\"", "alpine:init\"").Replace(valid),
		"extra-first-argument":  strings.Replace(valid, `"alpine:init")`, `"alpine:init",extra)`, 1),
		"extra-second-argument": strings.Replace(valid, `"alpine:initializing")`, `"alpine:initializing",extra)`, 1),
		"different-target":      strings.ReplaceAll(valid, "(document,", "(window,"),
		"qualified-target":      strings.ReplaceAll(valid, "(document,", "(window.document,"),
		"qualified-call":        strings.Replace(valid, "a(document,", "object.a(document,", 1),
		"bracket-call":          strings.Replace(valid, "a(document,", `object["a"](document,`, 1),
		"separated-events":      strings.Replace(valid, `),a(document`, `);other();a(document`, 1),
		"event-comment":         strings.Replace(valid, `),a(document`, `),/* gap */a(document`, 1),
		"continued-second-call": strings.Replace(valid, `"alpine:initializing");`, `"alpine:initializing")();`, 1),
		"escaped-event":         strings.Replace(valid, "alpine:init", `alpine\x3ainit`, 1),
		"wrong-api-case":        strings.Replace(valid, "dontAutoEvaluateFunctions", "DontAutoEvaluateFunctions", 1),
		"api-name-suffix":       strings.Replace(valid, "dontAutoEvaluateFunctions:", "dontAutoEvaluateFunctionsOther:", 1),
		"quoted-api-key":        strings.Replace(valid, "dontAutoEvaluateFunctions:", `"dontAutoEvaluateFunctions":`, 1),
		"api-read":              alpineEvents + `use(core.flushAndStopDeferringMutations,core.dontAutoEvaluateFunctions,core.disableEffectScheduling,core.startObservingMutations,core.stopObservingMutations,core.setReactivityEngine);`,
		"called-member":         strings.Replace(valid, "disableEffectScheduling:d", "disableEffectScheduling:d()", 1),
		"literal-member":        strings.Replace(valid, "disableEffectScheduling:d", "disableEffectScheduling:0", 1),
		"qualified-member":      strings.Replace(valid, "disableEffectScheduling:d", "disableEffectScheduling:object.d", 1),
		"reordered-members":     strings.Replace(valid, "startObservingMutations:e,stopObservingMutations:f", "stopObservingMutations:f,startObservingMutations:e", 1),
		"intervening-member":    strings.Replace(valid, "disableEffectScheduling:d,", "disableEffectScheduling:d,other:h,", 1),
		"api-comment":           strings.Replace(valid, "disableEffectScheduling:d,", "disableEffectScheduling:d,/* gap */", 1),
		"split-api-objects":     strings.Replace(valid, "disableEffectScheduling:d,", "disableEffectScheduling:d};var other={", 1),
		"continued-last-value":  strings.Replace(valid, "setReactivityEngine:g}", "setReactivityEngine:g.other}", 1),
		"incomplete-fragment":   strings.Replace(valid, "setReactivityEngine:g}", "setReactivityEngine:g", 1),
	}
	for _, member := range []string{"flushAndStopDeferringMutations:b,", "dontAutoEvaluateFunctions:c,", "disableEffectScheduling:d,", "startObservingMutations:e,", "stopObservingMutations:f,"} {
		cases["missing-"+member] = strings.Replace(valid, member, "", 1)
	}
	cases["missing-last-member"] = strings.Replace(valid, ",setReactivityEngine:g", "", 1)
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestAlpineSourceIsolationAndCoexistence(t *testing.T) {
	engine := bundledEngine(t)
	valid := alpineEvents + "var core=" + alpineAPI + ";"
	one, two := "https://example.test/one?private-token=1", "https://example.test/two"
	for name, input := range map[string]detect.Input{
		"html":             {HTML: []byte("<script>" + valid + "</script>")},
		"headers-cookies":  {Headers: http.Header{"X-Example": {valid}}, CookieNames: []string{valid}},
		"css":              {Assets: []detect.Asset{cssAsset(one, valid)}},
		"inline-css":       {InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(valid)}}},
		"empty-url":        {Assets: []detect.Asset{scriptAsset("", valid)}},
		"filename":         {Assets: []detect.Asset{scriptAsset("https://example.test/alpine.min.js", "generic")}},
		"split-files":      {Assets: []detect.Asset{scriptAsset(one, alpineEvents), scriptAsset(two, alpineAPI)}},
		"same-url-parts":   {Assets: []detect.Asset{scriptAsset(one, alpineEvents), scriptAsset(one, alpineAPI)}},
		"split-kinds":      {Assets: []detect.Asset{scriptAsset(one, alpineEvents), cssAsset(two, alpineAPI)}},
		"split-page-asset": {HTML: []byte(alpineEvents), Assets: []detect.Asset{scriptAsset(one, alpineAPI)}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(input); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
	input := detect.Input{Assets: []detect.Asset{scriptAsset(one, valid+valid), scriptAsset(two, alpineEvents+"var core="+alpineShorthand+";"), scriptAsset(one, valid)}}
	requireAlpine(t, engine.Detect(input), one, two)
	got := engine.Detect(input)
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Fatal("unstable evidence")
	}
	got[0].Evidence[0].AssetURL = "changed"
	got[0].Evidence[0].Signals[0].Source = detect.HTML
	requireAlpine(t, engine.Detect(input), one, two)
	if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
		t.Fatalf("retained findings=%+v", empty)
	}
	input.HTML = []byte(astroGenerator)
	input.Headers = http.Header{"Server": {"nginx"}}
	input.Assets[0].Body = []byte(valid + jqueryPrototype + jqueryExpando)
	got = engine.Detect(input)
	var ids []string
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	if !reflect.DeepEqual(ids, []string{"alpinejs", "astro", "jquery", "nginx"}) || got[0].State != detect.Inferred || got[3].State != detect.Detected {
		t.Fatalf("findings=%+v", got)
	}
}
