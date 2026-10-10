package assets_test

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/assets"
)

const page = "https://example.test/docs/page?view=one"

func extract(t *testing.T, markup string) assets.Result {
	t.Helper()
	got, err := assets.Extract(page, []byte(markup), assets.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return got
}

func TestReferenceExtraction(t *testing.T) {
	got := extract(t, `<!doctype html><html><head>
<SCRIPT SRC='../app.js?a=1&amp;b=2#part'></SCRIPT>
<link HREF=/main.css REL="alternate StyleSheet" type="text/css">
<script type=module src="//example.test/module"></script>
<script nomodule src="legacy.js"></script>
<link rel=stylesheet href="?sheet=1">
</head><body><a href="/page2">link</a><img src="/image.png"></body></html>`)
	want := []assets.Reference{
		{URL: "https://example.test/app.js?a=1&b=2", Kind: assets.JavaScript},
		{URL: "https://example.test/main.css", Kind: assets.Stylesheet},
		{URL: "https://example.test/module", Kind: assets.JavaScript},
		{URL: "https://example.test/docs/legacy.js", Kind: assets.JavaScript},
		{URL: "https://example.test/docs/page?sheet=1", Kind: assets.Stylesheet},
	}
	if !reflect.DeepEqual(got.References, want) || got.Truncated || got.Skipped != 0 || got.Duplicates != 0 {
		t.Fatalf("got=%#v want=%#v", got, want)
	}
}

func TestBaseResolution(t *testing.T) {
	for _, tc := range []struct {
		name, markup string
		want         []assets.Reference
		skipped      int
	}{
		{"relative-base", `<base href="../static/"><script src=app.js></script>`, []assets.Reference{{URL: "https://example.test/static/app.js", Kind: assets.JavaScript}}, 0},
		{"late-base", `<script src=app.js></script><base href=/static/>`, []assets.Reference{{URL: "https://example.test/static/app.js", Kind: assets.JavaScript}}, 0},
		{"first-base", `<base target=_blank><base href=/one/><base href=/two/><script src=app.js></script>`, []assets.Reference{{URL: "https://example.test/one/app.js", Kind: assets.JavaScript}}, 0},
		{"empty-first-base", `<base href=""><base href=/ignored/><script src=app.js></script>`, []assets.Reference{{URL: "https://example.test/docs/app.js", Kind: assets.JavaScript}}, 0},
		{"cross-origin-base", `<base href="https://cdn.invalid/files/"><script src=app.js></script><link rel=stylesheet href=/main.css><script src="https://example.test/absolute.js"></script>`, []assets.Reference{{URL: "https://example.test/absolute.js", Kind: assets.JavaScript}}, 2},
		{"invalid-first-base", `<base href="/%zz"><base href=/ignored/><script src=app.js></script><script src="https://example.test/absolute.js"></script>`, []assets.Reference{{URL: "https://example.test/absolute.js", Kind: assets.JavaScript}}, 1},
		{"credential-base", `<base href="https://private-user:private-secret@example.test/"><script src=app.js></script>`, []assets.Reference{}, 1},
		{"unsupported-base", `<base href="data:text/plain,ignored"><script src=/app.js></script>`, []assets.Reference{}, 1},
		{"inert-base", `<template><base href=/ignored/></template><script src=app.js></script>`, []assets.Reference{{URL: "https://example.test/docs/app.js", Kind: assets.JavaScript}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := extract(t, tc.markup)
			if !reflect.DeepEqual(got.References, tc.want) || got.Skipped != tc.skipped {
				t.Errorf("got=%#v want=%#v skipped=%d", got, tc.want, tc.skipped)
			}
		})
	}
}

func TestOriginAndURLBoundaries(t *testing.T) {
	for _, raw := range []string{
		"http://example.test/app.js", "https://sub.example.test/app.js", "https://example.test:444/app.js",
		"https://example.test.evil.invalid/app.js", "//other.invalid/app.js", "https://127.0.0.1/app.js",
		"https://example.test@other.invalid/app.js", "https://user:private-secret@example.test/app.js",
		"data:text/javascript,alert(1)", "javascript:alert(1)", "file:///app.js", "ftp://example.test/app.js",
		"https://example.test:/app.js", "https://example.test:0/app.js", "https://example.test:65536/app.js",
		"https:app.js", "/%zz", `\\other.invalid\app.js`, "/app\n.js", "/app\t.js", "/app\r.js",
		"", "   ", "#part", page, page + "#part",
	} {
		t.Run(fmt.Sprintf("%q", raw), func(t *testing.T) {
			got := extract(t, `<script src="`+raw+`"></script>`)
			if len(got.References) != 0 || got.Skipped != 1 {
				t.Errorf("ineligible URL accepted: %#v", got)
			}
		})
	}
	for _, raw := range []string{"HTTPS://EXAMPLE.TEST/app.js", "https://example.test:443/app.js", "https://example.test:00443/app.js", "/app.js?token=%zz"} {
		t.Run(raw, func(t *testing.T) {
			got := extract(t, `<script src="`+raw+`"></script>`)
			if len(got.References) != 1 || got.Skipped != 0 {
				t.Errorf("eligible URL rejected: %#v", got)
			}
		})
	}
	for _, localPage := range []string{"http://127.0.0.1:8080/page", "http://[::1]:8080/page", "http://localhost/page", "http://10.0.0.1/page"} {
		got, err := assets.Extract(localPage, []byte(`<script src=/app.js></script>`), assets.DefaultOptions())
		if err != nil || len(got.References) != 1 {
			t.Errorf("same-origin local reference rejected: result=%#v err=%v", got, err)
		}
	}
}

func TestMarkupDecoysAndTypes(t *testing.T) {
	for _, markup := range []string{
		`<!-- <script src=/fake.js></script><link rel=stylesheet href=/fake.css> -->`,
		`<script>const s = '<link rel=stylesheet href=/fake.css>';</script>`,
		`<style>/* <script src=/fake.js></script> */</style>`,
		`<textarea><link rel=stylesheet href=/fake.css></textarea>`,
		`<template><script src=/fake.js></script><link rel=stylesheet href=/fake.css></template>`,
		`<noscript><link rel=stylesheet href=/fake.css></noscript>`,
		`<svg><script href=/fake.js></script><foreignObject><script src=/fake.js></script></foreignObject></svg>`,
		`<math><mtext><script src=/fake.js></script></mtext></math>`,
		`<script data-src=/fake.js></script><link data-href=/fake.css rel=stylesheet>`,
		`<div title='<script src=/fake.js></script>'></div>`,
		`<script type=application/ld+json src=/fake.js></script>`,
		`<script type=importmap src=/fake.js></script>`,
		`<script type=speculationrules src=/fake.js></script>`,
		`<script type=text/plain src=/fake.js></script>`,
		`<script language=VBScript src=/fake.js></script>`,
		`<link rel=stylesheet type=text/plain href=/fake.css>`,
		`<link rel=preload as=script href=/fake.js><link rel=modulepreload href=/fake.js>`,
		`<link rel=notstylesheet href=/fake.css><link rel=stylesheet-extra href=/fake.css>`,
		"<link rel='preload\u00a0stylesheet' href=/fake.css>",
		`<script>import '/fake.js'</script><style>@import '/fake.css';</style>`,
	} {
		t.Run(markup, func(t *testing.T) {
			if got := extract(t, markup); len(got.References) != 0 {
				t.Errorf("decoy produced references: %#v", got)
			}
		})
	}
	for _, typ := range []string{"", "module", "text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript", " TEXT/JAVASCRIPT "} {
		if got := extract(t, `<script type="`+typ+`" src=/app></script>`); len(got.References) != 1 {
			t.Errorf("supported type %q not extracted: %#v", typ, got)
		}
	}
	// The parser, not regex matching, determines duplicate attributes and nesting.
	got := extract(t, `<SCRIPT SRC=/first.js src=/second.js></SCRIPT><link rel=stylesheet href=/first.css href=/second.css>`)
	if !reflect.DeepEqual(got.References, []assets.Reference{{URL: "https://example.test/first.js", Kind: assets.JavaScript}, {URL: "https://example.test/first.css", Kind: assets.Stylesheet}}) {
		t.Errorf("duplicate attribute policy changed: %#v", got)
	}
}

func TestDeduplicationAndLimits(t *testing.T) {
	markup := `<script src=/a.js#one></script><script src="https://EXAMPLE.TEST:00443/a.js#two"></script>
<script src=../a.js></script><link rel=stylesheet href=/a.js>
<script src="/a.js?v=1"></script><script src="/a.js?v=2"></script>
<script src="/a%2F.js"></script><script src="/a/.js"></script>`
	got := extract(t, markup)
	if len(got.References) != 5 || got.Duplicates != 3 || got.Truncated {
		t.Fatalf("deduplication/limit mismatch: %#v", got)
	}
	if extra := extract(t, markup+`<script src=/overflow.js></script>`); !extra.Truncated || !reflect.DeepEqual(extra.References, got.References) {
		t.Errorf("cap did not preserve stable first candidates: %#v", extra)
	}
	options := assets.DefaultOptions()
	options.MaxReferences = 1
	limited, err := assets.Extract(page, []byte(`<script src=https://other.invalid/a.js></script><script src=/one.js></script><script src=/two.js></script><script src=/one.js></script>`), options)
	if err != nil || !limited.Truncated || limited.Skipped != 1 || limited.Duplicates != 1 || len(limited.References) != 1 {
		t.Errorf("candidate budget/counts mismatch: %#v err=%v", limited, err)
	}
	for _, delta := range []int64{0, -1} {
		options = assets.DefaultOptions()
		options.MaxHTMLBytes = int64(len(markup)) + delta
		_, err := assets.Extract(page, []byte(markup), options)
		if (delta == 0 && err != nil) || (delta < 0 && !errors.Is(err, assets.ErrHTMLLimit)) {
			t.Errorf("HTML budget delta=%d err=%v", delta, err)
		}
	}
	for i := 0; i < 3; i++ {
		if next := extract(t, markup); !reflect.DeepEqual(next, got) {
			t.Error("extraction order is not deterministic")
		}
	}
}

func TestExtractionInputFailures(t *testing.T) {
	for _, raw := range []string{"not a URL", "ftp://example.test/", "https://private-user:private-password@example.test/"} {
		got, err := assets.Extract(raw, nil, assets.DefaultOptions())
		if err == nil || got.References != nil || strings.Contains(err.Error(), "private-") {
			t.Errorf("invalid page URL: result=%#v err=%v", got, err)
		}
	}
	for _, options := range []assets.Options{{}, {MaxHTMLBytes: 1, MaxReferences: -1}, {MaxHTMLBytes: -1, MaxReferences: 1}} {
		if _, err := assets.Extract(page, nil, options); err == nil {
			t.Error("invalid options accepted")
		}
	}
	if got, err := assets.Extract(page, []byte{0xff}, assets.DefaultOptions()); !errors.Is(err, assets.ErrInvalidHTML) || got.References != nil {
		t.Errorf("invalid UTF-8: result=%#v err=%v", got, err)
	}
	deep := strings.Repeat("<div>", 600) + `<script src=/a.js></script>` + strings.Repeat("</div>", 600)
	if got, err := assets.Extract(page, []byte(deep), assets.DefaultOptions()); !errors.Is(err, assets.ErrHTMLParse) || got.References != nil {
		t.Errorf("parser failure returned references: result=%#v err=%v", got, err)
	}
	if got := extract(t, ""); got.References == nil || len(got.References) != 0 || got.Truncated {
		t.Errorf("empty extraction should be successful with a nonnil empty slice: %#v", got)
	}
}
