package detect_test

import (
	"testing"

	"webscan/internal/detect"
)

func TestNextScriptAttributes(t *testing.T) {
	engine := bundledEngine(t)
	for _, marker := range []struct {
		name, value, other string
	}{
		{"id", "__NEXT_DATA__", `<script src="/_next/static/chunks/main.js"></script>`},
		{"src", "/_next/static/chunks/main.js", `<script id="__NEXT_DATA__"></script>`},
	} {
		for _, quote := range []string{`"`, `'`} {
			outerQuote := `'`
			if quote == `'` {
				outerQuote = `"`
			}
			attribute := marker.name + " = " + quote + marker.value + quote
			for _, tc := range []struct {
				name, tag string
				want      bool
			}{
				{"bare", "<script " + attribute + ">", true},
				{"attributes-before-and-after", "<SCRIPT async nonce='fixture' " + attribute + ` defer data-other=fixture>`, true},
				{"whitespace", "<script\n\t" + attribute + "\f >", true},
				{"self-closing", "<script " + attribute + " />", true},
				{"custom-tag", "<script-widget " + attribute + ">", false},
				{"namespaced-tag", "<script:widget " + attribute + ">", false},
				{"quoted-example", "<script data-example=" + outerQuote + " " + attribute + " " + outerQuote + ">", false},
				{"data-attribute", "<script data-" + attribute + ">", false},
				{"missing-tag-close", "<script " + attribute + " ", false},
				{"unfinished-later-attribute", "<script " + attribute + ` nonce="unfinished`, false},
				{"missing-attribute-separator", `<script nonce="fixture"` + attribute + ">", false},
				{"missing-tag-separator", "<script/ " + attribute + ">", false},
			} {
				t.Run(marker.name+"/"+quote+"/"+tc.name, func(t *testing.T) {
					// Put the complete counterpart first so it cannot close an
					// intentionally truncated opening tag in the candidate.
					got := engine.Detect(detect.Input{HTML: []byte(marker.other + tc.tag)})
					if !tc.want {
						if len(got) != 0 {
							t.Fatalf("unexpected findings: %+v", got)
						}
						return
					}
					if len(got) != 1 || got[0].ID != "nextjs" || got[0].State != detect.Inferred {
						t.Fatalf("findings=%+v, want only inferred Next.js", got)
					}
					if len(got[0].Evidence) != 1 || got[0].Evidence[0].RuleID != "pages-html-markers" || len(got[0].Evidence[0].Signals) != 2 {
						t.Fatalf("missing paired-marker evidence: %+v", got[0].Evidence)
					}
				})
			}
		}
	}
}

func TestNextAssetURLPaths(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct {
		name string
		want bool
		urls []string
	}{
		{"path-marker", true, []string{
			"/_next/static/chunks/main.js",
			"/docs/_next/static/chunks/main.js",
			"/docs/v1/_next/static/chunks/main.js?v=1#asset",
			"https://cdn.example.test/_next/static/chunks/main.js",
			"http://cdn.example.test/docs/_next/static/chunks/main.js",
			"HTTPS://cdn.example.test/docs/_next/static/chunks/main.js?v=1",
			"//cdn.example.test/docs/_next/static/chunks/main.js",
			"//_next/docs/_next/static/chunks/main.js",
			"https://cdn.example.test:8443/docs/_next/static/chunks/main.js",
			"https://[::1]:8080/_next/static/chunks/main.js",
			"docs/_next/static/chunks/main.js",
			"./_next/static/chunks/main.js",
			"../docs/_next/static/chunks/main.js",
		}},
		{"not-a-path-marker", false, []string{
			"https://_next/static/chunks/main.js",
			"http://_next/static/chunks/main.js",
			"//_next/static/chunks/main.js",
			"https://_next/static/main.js?path=/_next/static/main.js",
			"https://cdn.example.test/main.js?path=/_next/static/main.js",
			"//cdn.example.test/main.js#/_next/static/main.js",
			"docs/main.js?path=/_next/static/main.js",
			"/_next/staticish/chunks/main.js",
			"/other_next/static/chunks/main.js",
			"/_NEXT/static/chunks/main.js",
			"/_next/STATIC/chunks/main.js",
			"/_next/static/",
			"/_next/static/?v=1",
			"/_next/static/#asset",
			"https:///docs/_next/static/chunks/main.js",
			"///_next/static/chunks/main.js",
			"https:/_next/static/chunks/main.js",
			`https:\\cdn.example.test\_next/static/chunks/main.js`,
			"ftp://cdn.example.test/_next/static/chunks/main.js",
			"data:text/javascript,/_next/static/chunks/main.js",
			"javascript:load(/_next/static/chunks/main.js)",
		}},
	} {
		for _, url := range tc.urls {
			for _, quote := range []string{`"`, `'`} {
				t.Run(tc.name+"/"+quote+"/"+url, func(t *testing.T) {
					body := `<script id="__NEXT_DATA__"></script><script SRC = ` + quote + url + quote + ` async></script>`
					got := engine.Detect(detect.Input{HTML: []byte(body)})
					if !tc.want {
						if len(got) != 0 {
							t.Fatalf("unexpected findings: %+v", got)
						}
						return
					}
					if len(got) != 1 || got[0].ID != "nextjs" || got[0].State != detect.Inferred {
						t.Fatalf("findings=%+v, want only inferred Next.js", got)
					}
				})
			}
		}
	}
}
