package detect_test

import (
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const swiperDefaults = `{slideBlankClass:"swiper-slide-blank",slideActiveClass:"swiper-slide-active",slideVisibleClass:"swiper-slide-visible",slideFullyVisibleClass:"swiper-slide-fully-visible",slideNextClass:"swiper-slide-next",slidePrevClass:"swiper-slide-prev",wrapperClass:"swiper-wrapper"}`
const swiperInitialization = `s.eventsListeners={},s.eventsAnyListeners=[],s.modules=[...s.__modules__];`

func requireSwiper(t *testing.T, got []detect.Finding, urls ...string) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "swiper" || got[0].Name != "Swiper" || got[0].Category != detect.JSLibrary || got[0].State != detect.Inferred || len(got[0].Evidence) != len(urls) {
		t.Fatalf("findings=%+v want URLs=%v", got, urls)
	}
	for i, url := range urls {
		e := got[0].Evidence[i]
		if e.RuleID != "asset-core-runtime" || e.AssetURL != url || e.InferredFrom != "" || e.StyleBlock != 0 || e.Description == "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}) {
			t.Fatalf("evidence=%+v want URL=%s", e, url)
		}
		for _, raw := range []string{"private-", "slideBlankClass", "__modules__", "11.2.10", "12.0.3", "14.4.0"} {
			if strings.Contains(e.Description, raw) {
				t.Errorf("raw source/version in description: %s", e.Description)
			}
		}
	}
}

func TestSwiperRuntimeAssets(t *testing.T) {
	engine := bundledEngine(t)
	valid := "var defaults=" + swiperDefaults + ";" + swiperInitialization
	cases := map[string]string{
		"compact":                valid,
		"fallback":               strings.Replace(valid, "...s.__modules__", "...s.__modules__||[]", 1),
		"parenthesized-fallback": strings.Replace(valid, "...s.__modules__", "...(s.__modules__||[])", 1),
		"single-quotes":          strings.ReplaceAll(valid, `"`, `'`),
		"renamed":                strings.ReplaceAll(valid, "s.", "$instance."),
		"spaced":                 strings.NewReplacer(":", " : ", ",", " ,\n ", "=", " = ", ".events", " . events", "...s", "... s").Replace(valid),
		"semicolon-assignments":  strings.ReplaceAll(valid, "={},s", "={};s"),
		"both-semicolons":        strings.ReplaceAll(strings.ReplaceAll(valid, "={},s", "={};s"), "=[],s", "=[];s"),
		"other-defaults-around":  strings.Replace(strings.Replace(valid, "{slideBlank", "{before:0,slideBlank", 1), `"swiper-wrapper"}`, `"swiper-wrapper",after:0}`, 1),
		"trailing-default-comma": strings.Replace(valid, `"swiper-wrapper"}`, `"swiper-wrapper",}`, 1),
		"reversed-groups":        swiperInitialization + "var defaults=" + swiperDefaults + ";",
		"repeated":               valid + valid,
		// These matches describe source text, not scope, identifier equality or execution.
		"different-receivers": strings.Replace(valid, "s.eventsAnyListeners", "other.eventsAnyListeners", 1),
		"commented":           "/* " + valid + " */",
	}
	for _, name := range []string{"swiper-core.js", "swiper-core.min.js", "swiper-core-fallback.js", "swiper-core-fallback.min.js"} {
		cases[name] = string(htmlFixture(t, name))
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			url := "https://example.test/renamed?private-token=1"
			requireSwiper(t, engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset(url, body)}}), url)
		})
	}
}

func TestSwiperRuntimeNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	valid := "var defaults=" + swiperDefaults + ";" + swiperInitialization
	cases := map[string]string{
		"defaults-only":             swiperDefaults,
		"initialization-only":       swiperInitialization,
		"banner":                    "/*! Swiper 14.4.0 */",
		"consumer":                  `new Swiper('.swiper',{loop:true});slider.slideNext();`,
		"classes":                   `<div class="swiper"><div class="swiper-wrapper"><div class="swiper-slide"></div></div></div>`,
		"identity-only":             `s.__swiper__=true;` + swiperDefaults,
		"css":                       `.swiper-wrapper{display:flex}.swiper-slide{flex-shrink:0}`,
		"missing-member":            strings.Replace(valid, `slideVisibleClass:"swiper-slide-visible",`, "", 1),
		"member-case":               strings.Replace(valid, "slideBlankClass", "slideblankClass", 1),
		"member-prefix":             strings.Replace(valid, "slideBlankClass", "otherSlideBlankClass", 1),
		"value-suffix":              strings.Replace(valid, `"swiper-slide-next"`, `"swiper-slide-next-other"`, 1),
		"quoted-key":                strings.Replace(valid, "slideBlankClass:", `"slideBlankClass":`, 1),
		"computed-value":            strings.Replace(valid, `"swiper-wrapper"`, `"swiper-wrapper"+suffix`, 1),
		"split-objects":             strings.Replace(valid, "slideNextClass:", "};var other={slideNextClass:", 1),
		"extra-member":              strings.Replace(valid, "slidePrevClass:", "extra:0,slidePrevClass:", 1),
		"reordered-members":         strings.Replace(valid, `slideNextClass:"swiper-slide-next",slidePrevClass:"swiper-slide-prev"`, `slidePrevClass:"swiper-slide-prev",slideNextClass:"swiper-slide-next"`, 1),
		"default-comment":           strings.Replace(valid, "slideNextClass:", "/* gap */slideNextClass:", 1),
		"nonempty-listeners":        strings.Replace(valid, "eventsListeners={}", "eventsListeners={ready:fn}", 1),
		"nonempty-any-listeners":    strings.Replace(valid, "eventsAnyListeners=[]", "eventsAnyListeners=[fn]", 1),
		"initialization-case":       strings.Replace(valid, "eventsAnyListeners", "eventsanyListeners", 1),
		"initialization-comparison": strings.Replace(valid, "eventsListeners=", "eventsListeners===", 1),
		"qualified-first-receiver":  strings.Replace(valid, "s.eventsListeners", "global.s.eventsListeners", 1),
		"computed-receiver":         strings.Replace(valid, "s.eventsListeners", `s["eventsListeners"]`, 1),
		"assignment-gap":            strings.Replace(valid, "s.eventsAnyListeners", "notify();s.eventsAnyListeners", 1),
		"assignment-comment":        strings.Replace(valid, "s.eventsAnyListeners", "/* gap */s.eventsAnyListeners", 1),
		"missing-spread":            strings.Replace(valid, "...s.__modules__", "s.__modules__", 1),
		"wrong-module-source":       strings.Replace(valid, "__modules__", "modules", 1),
		"extra-module":              strings.Replace(valid, "...s.__modules__", "...s.__modules__,extra", 1),
		"wrong-fallback":            strings.Replace(valid, "...s.__modules__", "...s.__modules__||[extra]", 1),
		"unbalanced-fallback":       strings.Replace(valid, "...s.__modules__", "...(s.__modules__||[]", 1),
		"incomplete-array":          strings.TrimSuffix(valid, "];"),
		"continued-array":           strings.TrimSuffix(valid, ";") + ".concat(other);",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/file", body)}}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestSwiperIsolationAndEvidence(t *testing.T) {
	engine := bundledEngine(t)
	valid := "var defaults=" + swiperDefaults + ";" + swiperInitialization
	one, two := "https://example.test/one?private-token=1", "https://example.test/two"
	for name, input := range map[string]detect.Input{
		"html-inline-js":   {HTML: []byte("<script>" + valid + "</script>")},
		"headers-cookies":  {Headers: http.Header{"X-Example": {valid}}, CookieNames: []string{valid}},
		"css":              {Assets: []detect.Asset{cssAsset(one, valid)}},
		"inline-css":       {InlineStyles: []detect.InlineStyle{{Index: 1, Body: []byte(valid)}}},
		"empty-url":        {Assets: []detect.Asset{scriptAsset("", valid)}},
		"filename":         {Assets: []detect.Asset{scriptAsset("https://example.test/swiper-bundle.min.js", "generic")}},
		"split-files":      {Assets: []detect.Asset{scriptAsset(one, swiperDefaults), scriptAsset(two, swiperInitialization)}},
		"same-url-parts":   {Assets: []detect.Asset{scriptAsset(one, swiperDefaults), scriptAsset(one, swiperInitialization)}},
		"split-kinds":      {Assets: []detect.Asset{scriptAsset(one, swiperDefaults), cssAsset(two, swiperInitialization)}},
		"split-page-asset": {HTML: []byte(swiperDefaults), Assets: []detect.Asset{scriptAsset(one, swiperInitialization)}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(input); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
	input := detect.Input{Assets: []detect.Asset{scriptAsset(one, valid), scriptAsset(two, valid), scriptAsset(one, valid)}}
	got := engine.Detect(input)
	requireSwiper(t, got, one, two)
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Fatal("unstable findings/evidence")
	}
	got[0].Evidence[0].AssetURL = "changed"
	got[0].Evidence[0].Signals[0].Source = detect.HTML
	requireSwiper(t, engine.Detect(input), one, two)
	if got := engine.Detect(detect.Input{}); len(got) != 0 {
		t.Fatalf("retained findings=%+v", got)
	}
	input.HTML = []byte(astroGenerator)
	input.Headers = http.Header{"Server": {"nginx"}}
	input.Assets[0].Body = []byte(valid + jqueryPrototype + jqueryExpando)
	got = engine.Detect(input)
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
	}
	if !reflect.DeepEqual(ids, []string{"astro", "jquery", "nginx", "swiper"}) || got[3].State != detect.Inferred || got[2].State != detect.Detected || len(got[3].Evidence) != 2 {
		t.Fatalf("mixed findings=%+v", got)
	}
}
