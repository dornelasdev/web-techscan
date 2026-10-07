package detect_test

import (
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const nuxtDataScript = `<script type="application/json" id="__NUXT_DATA__">[]</script>`
const nuxtAssetScript = `<script type="module" src="/_nuxt/entry.js"></script>`

func requireNuxt(t *testing.T, got []detect.Finding, html, header bool) {
	t.Helper()
	if !html && !header {
		if len(got) != 0 {
			t.Fatalf("unexpected findings: %+v", got)
		}
		return
	}
	state := detect.Inferred
	if header {
		state = detect.Detected
	}
	if len(got) != 1 || got[0].ID != "nuxt" || got[0].Name != "Nuxt" || got[0].Category != detect.Framework || got[0].State != state {
		t.Fatalf("want only Nuxt (%s), without language/runtime guesses; got %+v", state, got)
	}
	want := []string{}
	if html {
		want = append(want, "payload-html-markers")
	}
	if header {
		want = append(want, "powered-by-header")
	}
	if len(got[0].Evidence) != len(want) {
		t.Fatalf("evidence=%+v want rules=%v", got[0].Evidence, want)
	}
	for i, evidence := range got[0].Evidence {
		signals := []detect.Signal{{Source: detect.HTML}, {Source: detect.HTML}}
		if want[i] == "powered-by-header" {
			signals = []detect.Signal{{Source: detect.Header, Name: "X-Powered-By"}}
		}
		if evidence.RuleID != want[i] || evidence.Description == "" || evidence.InferredFrom != "" || !reflect.DeepEqual(evidence.Signals, signals) {
			t.Errorf("unexpected evidence: %+v", evidence)
		}
	}
}

func TestNuxtHeaderAndFixture(t *testing.T) {
	engine := bundledEngine(t)
	fixture := htmlFixture(t, "nuxt-payload.html")
	for _, value := range []string{"Nuxt", " NUXT\t", "nuxt"} {
		for _, html := range []bool{false, true} {
			t.Run(value+"/html="+strconv.FormatBool(html), func(t *testing.T) {
				input := detect.Input{Headers: http.Header{"x-powered-by": {"unrelated", value, value}}}
				if html {
					input.HTML = append(append([]byte{}, fixture...), fixture...)
				}
				requireNuxt(t, engine.Detect(input), html, true)
			})
		}
	}
	requireNuxt(t, engine.Detect(detect.Input{HTML: fixture}), true, false)
	for _, value := range []string{"Nuxt.js", "Nuxt/3", "Nuxt-compatible", "NotNuxt", "Nuxtish", "Nuxt, Express", "Nuxt\n", "Nuxt\x00"} {
		t.Run("header-near-miss/"+value, func(t *testing.T) {
			requireNuxt(t, engine.Detect(detect.Input{Headers: http.Header{"X-Powered-By": {value}}}), false, false)
		})
	}
	requireNuxt(t, engine.Detect(detect.Input{Headers: http.Header{"Server": {"Nuxt"}, "X-Nuxt": {"Nuxt"}}, CookieNames: []string{"Nuxt", "__NUXT_DATA__"}}), false, false)
}

func TestNuxtHTMLBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for _, marker := range []struct{ name, value, other string }{
		{"id", "__NUXT_DATA__", nuxtAssetScript},
		{"src", "/_nuxt/entry.js", nuxtDataScript},
	} {
		for _, quote := range []string{`"`, `'`} {
			outer := `'`
			if quote == `'` {
				outer = `"`
			}
			attr := marker.name + "=" + quote + marker.value + quote
			for _, tc := range []struct {
				name, tag string
				want      bool
			}{
				{"normal", "<script " + attr + ">", true},
				{"other-attributes", "<SCRIPT nonce='fixture'\n" + attr + " defer data-ssr=true >", true},
				{"data-attribute", "<script data-" + attr + ">", false},
				{"custom-tag", "<script-widget " + attr + ">", false},
				{"wrong-tag", "<div " + attr + ">", false},
				{"quoted-example", "<script data-example=" + outer + " " + attr + " " + outer + ">", false},
				{"truncated", "<script " + attr, false},
				{"missing-separator", "<script nonce='x'" + attr + ">", false},
				{"unfinished-attribute", "<script " + attr + ` nonce="unfinished`, false},
			} {
				t.Run(marker.name+quote+tc.name, func(t *testing.T) {
					requireNuxt(t, engine.Detect(detect.Input{HTML: []byte(marker.other + tc.tag)}), tc.want, false)
				})
			}
		}
	}
	for _, body := range []string{
		nuxtDataScript, nuxtAssetScript, "__NUXT_DATA__ /_nuxt/entry.js",
		`<div id="__nuxt"></div>` + nuxtAssetScript,
		`<script>window.__NUXT__={}</script>` + nuxtAssetScript,
		`<script data-nuxt-data="custom-app"></script>` + nuxtAssetScript,
		`<script id="__nuxt_data__"></script>` + nuxtAssetScript,
		`<script id="__NUXT_DATA__-extra"></script>` + nuxtAssetScript,
		`&lt;script id="__NUXT_DATA__"&gt;[]&lt;/script&gt;` + nuxtAssetScript,
		nuxtDataScript + `<link rel="modulepreload" href="/_nuxt/entry.js">`,
		nuxtDataScript + `<script src="/_next/static/entry.js"></script>`,
		`<script id="__NEXT_DATA__"></script>` + nuxtAssetScript,
	} {
		requireNuxt(t, engine.Detect(detect.Input{HTML: []byte(body)}), false, false)
	}
	// Explicitly preserve the documented raw-HTML limitation: no DOM/comment parsing.
	requireNuxt(t, engine.Detect(detect.Input{HTML: []byte("<!--" + nuxtDataScript + nuxtAssetScript + "-->")}), true, false)
}

func TestNuxtAssetPaths(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct {
		want bool
		urls []string
	}{
		{true, []string{"/_nuxt/entry.js", "/docs/_nuxt/entry.js?v=1#asset", "https://cdn.example.test/_nuxt/entry.js", "//cdn.example.test/docs/_nuxt/entry.js", "./_nuxt/entry.js", "../docs/_nuxt/entry.js"}},
		{false, []string{"https://_nuxt/entry.js", "//_nuxt/entry.js", "/entry.js?path=/_nuxt/entry.js", "/entry.js#/_nuxt/entry.js", "/_nuxtish/entry.js", "/_NUXT/entry.js", "/_nuxt/", "/_nuxt/?v=1", "https:///_nuxt/entry.js", "///_nuxt/entry.js", `https:\\cdn.example.test\_nuxt/entry.js`, "data:text/javascript,/_nuxt/entry.js", "javascript:load('/_nuxt/entry.js')", "/custom-assets/entry.js"}},
	} {
		for _, url := range tc.urls {
			for _, quote := range []string{`"`, `'`} {
				t.Run(url+quote, func(t *testing.T) {
					body := nuxtDataScript + `<script SRC=` + quote + url + quote + ` type="module"></script>`
					requireNuxt(t, engine.Detect(detect.Input{HTML: []byte(body)}), tc.want, false)
				})
			}
		}
	}
}

func TestNuxtCoexistsWithNext(t *testing.T) {
	engine := bundledEngine(t)
	body := nuxtDataScript + nuxtAssetScript + `<script id="__NEXT_DATA__"></script><script src="/_next/static/entry.js"></script>`
	got := engine.Detect(detect.Input{HTML: []byte(body), Headers: http.Header{"X-Powered-By": {"Next.js"}}})
	if len(got) != 2 || got[0].ID != "nextjs" || got[0].State != detect.Detected || got[1].ID != "nuxt" || got[1].State != detect.Inferred {
		t.Fatalf("cross-framework evidence leaked: %+v", got)
	}
	if strings.Contains(got[1].Evidence[0].Description, "NEXT") {
		t.Error("Nuxt evidence uses Next.js markers")
	}
}
