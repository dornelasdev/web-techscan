package assets_test

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/assets"
	"webscan/internal/fetch"
)

func inlineCSS(t *testing.T, markup string) assets.InlineCSSCollection {
	t.Helper()
	result, err := assets.Extract(page, []byte(markup), assets.DefaultOptions())
	if err != nil {
		t.Fatal(err)
	}
	return result.InlineCSS
}

func TestInlineCSSSelectionAndBlockIdentity(t *testing.T) {
	markup := `<style type="application/json">ignored</style>
<!-- <style>comment</style> -->
<template><style>template</style></template>
<noscript><style>fallback</style></noscript>
<svg><style>foreign</style><foreignObject><style>foreign HTML</style></foreignObject></svg>
<math><style>foreign math</style></math>
<textarea><style>textarea</style></textarea>
<script>const x = '<style>JS string</style>';</script>
<div style="attribute">fixture</div>
<STYLE type=" TeXt/CsS " media="print">a{content:"&amp;"}</STYLE>
<style></style><style type="">/* copied CSS */ b{color:red}</style>`
	got := inlineCSS(t, markup)
	want := []assets.InlineStyle{
		{Index: 1, Body: []byte(`a{content:"&amp;"}`)},
		{Index: 2, Body: []byte{}},
		{Index: 3, Body: []byte(`/* copied CSS */ b{color:red}`)},
	}
	if got.Status != "complete" || got.Reason != "" || got.Seen != 3 || got.Collected != 3 || got.Skipped != 0 || got.Truncated || !reflect.DeepEqual(got.Blocks, want) || len(got.Items) != 3 {
		t.Fatalf("inline=%+v", got)
	}
	var total int64
	for i, block := range want {
		total += int64(len(block.Body))
		if got.Items[i] != (assets.InlineStyleItem{Index: i + 1, Status: "collected", Bytes: int64(len(block.Body))}) {
			t.Errorf("item=%+v", got.Items[i])
		}
	}
	if got.Bytes != total {
		t.Errorf("bytes=%d want=%d", got.Bytes, total)
	}
	if again := inlineCSS(t, markup); !reflect.DeepEqual(again, got) {
		t.Fatal("unstable inline order/indexing")
	}
	got.Blocks[0].Body[0] = 'z'
	if again := inlineCSS(t, markup); !reflect.DeepEqual(again.Blocks, want) {
		t.Fatal("capture mutated a later extraction")
	}
	if empty := inlineCSS(t, ""); empty.Status != "complete" || empty.Items == nil || empty.Blocks == nil || empty.Seen != 0 {
		t.Fatalf("empty=%+v", empty)
	}
}

func TestInlineCSSLimitsRejectWholeBlocks(t *testing.T) {
	comment := func(size int) string { return "/*" + strings.Repeat("0", size-4) + "*/" }
	atCap := comment(int(assets.MaxInlineStyleBytes))
	got := inlineCSS(t, "<style>"+atCap+"</style><style>"+atCap+"0</style><style>x{}</style>")
	if got.Status != "incomplete" || got.Reason != "block_byte_limit" || got.Seen != 3 || got.Collected != 2 || got.Skipped != 1 || got.Bytes != assets.MaxInlineStyleBytes+3 || len(got.Blocks) != 2 || got.Blocks[1].Index != 3 || got.Items[1].Reason != "block_byte_limit" || got.Items[1].Bytes != assets.MaxInlineStyleBytes+1 {
		t.Fatalf("per-block limit=%+v", got)
	}
	if string(got.Blocks[0].Body) != atCap {
		t.Fatal("exact per-block boundary rejected/truncated")
	}
	got = inlineCSS(t, "<style>"+atCap+"</style><style>"+comment(int(assets.MaxInlineStyleBytes)-4)+"</style><style>12345</style><style>1234</style>")
	if got.Status != "incomplete" || got.Reason != "total_byte_limit" || got.Collected != 3 || got.Skipped != 1 || got.Bytes != assets.MaxInlineCSSBytes || len(got.Blocks) != 3 || got.Blocks[2].Index != 4 || string(got.Blocks[2].Body) != "1234" || got.Items[2].Reason != "total_byte_limit" {
		t.Fatalf("aggregate limit=%+v", got)
	}
	markup := strings.Repeat("<style></style>", assets.MaxInlineStyleBlocks)
	if at := inlineCSS(t, markup); at.Status != "complete" || at.Collected != assets.MaxInlineStyleBlocks || at.Truncated {
		t.Fatalf("exact count cap=%+v", at)
	}
	got = inlineCSS(t, markup+"<style>omitted</style><style>also omitted</style>")
	if got.Status != "incomplete" || got.Reason != "block_limit" || !got.Truncated || got.Seen != assets.MaxInlineStyleBlocks+2 || got.Collected != assets.MaxInlineStyleBlocks || got.Skipped != 2 || len(got.Blocks) != assets.MaxInlineStyleBlocks || len(got.Items) != assets.MaxInlineStyleBlocks {
		t.Fatalf("count cap=%+v", got)
	}
}

func TestInlineCSSIndependentFromAssetSelectionAndFailures(t *testing.T) {
	markup := strings.Repeat(`<style>a{}</style>`, assets.MaxInlineStyleBlocks+1)
	for i := 0; i < 6; i++ {
		markup += fmt.Sprintf(`<script src="/asset-%d.js"></script>`, i)
	}
	markup += `<style>b{}</style>`
	for _, profile := range []string{"standard", "expanded"} {
		budget, _ := assets.BudgetForProfile(profile)
		calls := 0
		client := assetFetcher(func(context.Context, string, fetch.AssetOptions) (fetch.AssetResponse, error) {
			calls++
			return fetch.AssetResponse{StatusCode: 404}, fetch.ErrAssetStatus
		})
		got, err := assets.CollectWithBudget(context.Background(), client, assetPage(markup), budget)
		if err != nil || calls != 5 || got.Attempted != 5 || got.Collected != 0 || !got.Truncated || got.Reason != "reference_limit" || got.InlineCSS.Seen != 22 || got.InlineCSS.Collected != 20 || !got.InlineCSS.Truncated || len(got.InlineCSS.Blocks) != 20 {
			t.Fatalf("profile=%s collection=%+v err=%v", profile, got, err)
		}
	}
	// Local CSS caps do not change network scope completeness or byte counters.
	got := assets.Collect(context.Background(), nil, assetPage(strings.Repeat(`<style></style>`, 21)))
	if got.Status != "complete" || got.Truncated || got.Attempted != 0 || got.Usage != (fetch.BodyUsage{}) || got.InlineCSS.Status != "incomplete" {
		t.Fatalf("statuses conflated: %+v", got)
	}
}

func TestInlineCSSSkippedWhenWholeExtractionCannotBegin(t *testing.T) {
	for _, tc := range []struct{ name, typ, body, reason string }{
		{"non-html", "application/json", `<style>a{}</style>`, "unsupported_page_type"},
		{"xhtml", "application/xhtml+xml", `<style>a{}</style>`, "unsupported_page_type"},
		{"legacy-charset", "text/html; charset=iso-8859-1", `<style>a{}</style>`, "unsupported_page_type"},
		{"invalid-utf8", "text/html", string([]byte{0xff}), "invalid_utf8_html"},
		{"html-limit", "text/html", strings.Repeat("0", (2<<20)+1), "html_limit"},
		{"parse-error", "text/html", strings.Repeat("<div>", 600), "extraction_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := assetPage(tc.body)
			page.Headers.Set("Content-Type", tc.typ)
			got := assets.Collect(context.Background(), nil, page)
			if got.InlineCSS.Status != "skipped" || got.InlineCSS.Reason != tc.reason || len(got.InlineCSS.Blocks) != 0 {
				t.Fatalf("inline=%+v", got.InlineCSS)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got := assets.Collect(ctx, nil, assetPage(`<style>a{}</style>`)); got.InlineCSS.Status != "skipped" || got.InlineCSS.Reason != "canceled" {
		t.Fatalf("canceled=%+v", got.InlineCSS)
	}
}
