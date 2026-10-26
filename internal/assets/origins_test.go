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

func TestExternalOriginsNormalizationAndDeclarationCounts(t *testing.T) {
	markup := `<script src="https://CDN.test:00443/private-path?private-query=1#private-fragment"></script>
<script src="//cdn.test/another.js"></script>
<link rel="stylesheet" href="https://cdn.test:443/another.js">
<script src="http://cdn.test:00080/a.js"></script>
<link rel="stylesheet" href="https://cdn.test:0444/a.css">
<script src="https://[2001:DB8::1]:443/a.js"></script>
<link rel="stylesheet" href="https://[2001:db8::1]/b.css">
<script src="http://example.test/a.js"></script>
<script src="https://example.test:444/a.js"></script>
<script src="https://EXAMPLE.TEST:00443/local.js"></script>`
	got := extract(t, markup)
	want := []assets.ExternalOrigin{
		{Origin: "https://cdn.test", Scripts: 2, Stylesheets: 1},
		{Origin: "http://cdn.test", Scripts: 1},
		{Origin: "https://cdn.test:444", Stylesheets: 1},
		{Origin: "https://[2001:db8::1]", Scripts: 1, Stylesheets: 1},
		{Origin: "http://example.test", Scripts: 1},
		{Origin: "https://example.test:444", Scripts: 1},
	}
	if !reflect.DeepEqual(got.ExternalOrigins, want) || got.ExternalOriginsTruncated || got.Skipped != 9 || got.Duplicates != 0 || len(got.References) != 1 {
		t.Fatalf("summary=%+v", got)
	}
	for _, origin := range got.ExternalOrigins {
		if strings.Contains(origin.Origin, "private-") || strings.ContainsAny(origin.Origin, "?#@") {
			t.Fatalf("full asset URL leaked: %+v", origin)
		}
	}
	if again := extract(t, markup); !reflect.DeepEqual(again, got) {
		t.Fatal("external origin order or counts are unstable")
	}
}

func TestExternalOriginsUseExistingDeclarationAndBasePolicies(t *testing.T) {
	for _, tc := range []struct {
		name, markup string
		want         []assets.ExternalOrigin
	}{
		{"base-resolution", `<script src="app.js"></script><base href="https://CDN.test:443/files/"><link rel=stylesheet href=/main.css>`, []assets.ExternalOrigin{{Origin: "https://cdn.test", Scripts: 1, Stylesheets: 1}}},
		{"invalid-first-base", `<base href="/%zz"><base href="https://ignored.test/"><script src="relative.js"></script><script src="https://cdn.test/absolute.js"></script>`, []assets.ExternalOrigin{{Origin: "https://cdn.test", Scripts: 1}}},
		{"duplicate-url-declarations", `<script src="https://cdn.test/a.js"></script><script src="https://cdn.test/a.js#fragment"></script><link rel=stylesheet href="https://cdn.test/a.js">`, []assets.ExternalOrigin{{Origin: "https://cdn.test", Scripts: 2, Stylesheets: 1}}},
		{"empty", "", []assets.ExternalOrigin{}},
		{"decoys", `<!-- <script src="https://comment.test/a.js"></script> -->
<script>const s = '<link rel="stylesheet" href="https://string.test/a.css">';</script>
<style>/* <script src="https://style.test/a.js"></script> */</style>
<template><script src="https://template.test/a.js"></script></template>
<noscript><link rel=stylesheet href="https://noscript.test/a.css"></noscript>
<svg><foreignObject><script src="https://foreign.test/a.js"></script></foreignObject></svg>
<textarea><script src="https://textarea.test/a.js"></script></textarea>
<link rel=modulepreload href="https://preload.test/a.js">
<link rel=preload as=style href="https://preload.test/a.css">
<a href="https://anchor.test/a.js">link</a>
<script type=application/json src="https://json.test/a.js"></script>
<script language=vbscript src="https://legacy.test/a.js"></script>
<link rel=stylesheet type=text/plain href="https://plain.test/a.css">
<script src="https://private-user:private-password@credential.test/a.js"></script>
<script src="https://bad.test:0/a.js"></script>
<script src="https://bad.test:/a.js"></script>
<script src="https://bad.test/a\b.js"></script>
<script src="https://bad.test/a&#10;b.js"></script>
<script src="data:text/javascript,ignored"></script>`, []assets.ExternalOrigin{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := extract(t, tc.markup)
			if !reflect.DeepEqual(got.ExternalOrigins, tc.want) || got.ExternalOriginsTruncated {
				t.Fatalf("summary=%+v want=%+v", got, tc.want)
			}
		})
	}
}

func TestExternalOriginsHaveIndependentStorageAndFetchLimits(t *testing.T) {
	var markup strings.Builder
	for i := 0; i < 6; i++ {
		fmt.Fprintf(&markup, `<script src="/local-%d.js"></script>`, i)
	}
	externalStart := markup.Len()
	for i := 0; i < assets.MaxExternalOrigins; i++ {
		fmt.Fprintf(&markup, `<script src="https://cdn-%d.test/private-path?private-query"></script>`, i)
	}
	atCap := extract(t, markup.String())
	if len(atCap.ExternalOrigins) != assets.MaxExternalOrigins || atCap.ExternalOriginsTruncated || !atCap.Truncated || len(atCap.References) != 5 {
		t.Fatalf("at cap=%+v", atCap)
	}
	markup.WriteString(`<script src="https://overflow.test/a.js"></script><link rel=stylesheet href="https://cdn-0.test/b.css">`)
	got := extract(t, markup.String())
	if len(got.ExternalOrigins) != assets.MaxExternalOrigins || !got.ExternalOriginsTruncated || !got.Truncated || got.Skipped != assets.MaxExternalOrigins+2 || got.ExternalOrigins[0].Stylesheets != 1 || !reflect.DeepEqual(got.References, atCap.References) {
		t.Fatalf("past cap=%+v", got)
	}
	for i, origin := range got.ExternalOrigins {
		if origin.Origin != fmt.Sprintf("https://cdn-%d.test", i) || origin.Scripts != 1 {
			t.Fatalf("order/count changed: %+v", origin)
		}
	}
	// Discovery truncation alone does not truncate the eligible reference scope.
	got = extract(t, markup.String()[externalStart:])
	if !got.ExternalOriginsTruncated || got.Truncated || len(got.References) != 0 {
		t.Fatalf("origin and reference truncation conflated: %+v", got)
	}
}

func TestCollectExternalOriginsWithoutRequestingThem(t *testing.T) {
	page := assetPage(`<script src="https://cdn.test/private-path?private-query"></script><script src="/local.js"></script><link rel=stylesheet href="https://cdn.test/other.css">`)
	for _, fail := range []bool{false, true} {
		calls := 0
		client := assetFetcher(func(_ context.Context, target string, _ fetch.AssetOptions) (fetch.AssetResponse, error) {
			calls++
			if target != "https://example.test/local.js" {
				t.Fatalf("external origin requested: %s", target)
			}
			if fail {
				return fetch.AssetResponse{}, fetch.ErrAssetStatus
			}
			return fetch.AssetResponse{StatusCode: 200, Body: []byte("local")}, nil
		})
		got := assets.Collect(context.Background(), client, page)
		want := []assets.ExternalOrigin{{Origin: "https://cdn.test", Scripts: 1, Stylesheets: 1}}
		status := "complete"
		if fail {
			status = "incomplete"
		}
		if calls != 1 || got.Attempted != 1 || got.Status != status || got.SkippedDeclarations != 2 || !reflect.DeepEqual(got.ExternalOrigins, want) || got.ExternalOriginsTruncated {
			t.Fatalf("collection=%+v calls=%d", got, calls)
		}
	}
}

func TestCollectExternalOriginDiscoveryScope(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	canceled := assets.Collect(ctx, nil, assetPage(`<script src="https://cdn.test/a.js"></script>`))
	if canceled.Status != "skipped" || canceled.Reason != "canceled" || len(canceled.ExternalOrigins) != 0 || canceled.ExternalOriginsTruncated {
		t.Fatalf("canceled scope=%+v", canceled)
	}
	for _, tc := range []struct {
		name, contentType, body, reason string
	}{
		{"non-html", "application/json", `<script src="https://cdn.test/a.js"></script>`, "unsupported_page_type"},
		{"invalid-utf8", "text/html", string([]byte{0xff}), "invalid_utf8_html"},
		{"html-limit", "text/html", strings.Repeat(" ", (2<<20)+1), "html_limit"},
		{"parser-error", "text/html", strings.Repeat("<div>", 600), "extraction_failed"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := assetPage(tc.body)
			page.Headers.Set("Content-Type", tc.contentType)
			client := assetFetcher(func(context.Context, string, fetch.AssetOptions) (fetch.AssetResponse, error) {
				t.Fatal("unexpected asset request")
				return fetch.AssetResponse{}, nil
			})
			got := assets.Collect(context.Background(), client, page)
			if got.Status != "skipped" || got.Reason != tc.reason || len(got.ExternalOrigins) != 0 || got.ExternalOriginsTruncated {
				t.Fatalf("collection=%+v", got)
			}
		})
	}
	// An origin-only scope stays complete, even if discovery metadata truncates.
	var markup strings.Builder
	for i := 0; i <= assets.MaxExternalOrigins; i++ {
		fmt.Fprintf(&markup, `<script src="https://cdn-%d.test/a.js"></script>`, i)
	}
	got := assets.Collect(context.Background(), nil, assetPage(markup.String()))
	if got.Status != "complete" || !got.ExternalOriginsTruncated || got.Truncated || got.Attempted != 0 || len(got.ExternalOrigins) != assets.MaxExternalOrigins {
		t.Fatalf("origin-only scope=%+v", got)
	}
}
