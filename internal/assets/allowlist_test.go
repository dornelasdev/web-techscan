package assets_test

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"webscan/internal/assets"
	"webscan/internal/fetch"
)

func TestNormalizeAssetOrigins(t *testing.T) {
	inputs := []string{"HTTPS://CDN.test:00443/", "https://cdn.test", "http://cdn.test:00080", "https://cdn.test:0444", "https://[::1]:443/", "http://localhost:8080"}
	want := []string{"https://cdn.test", "http://cdn.test", "https://cdn.test:444", "https://[::1]", "http://localhost:8080"}
	got, err := assets.NormalizeOrigins(inputs)
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("origins=%v err=%v", got, err)
	}
	got[0] = "changed"
	if inputs[0] != "HTTPS://CDN.test:00443/" {
		t.Fatal("normalization mutated caller data")
	}
	if empty, err := assets.NormalizeOrigins(nil); err != nil || empty == nil || len(empty) != 0 {
		t.Fatalf("empty origins=%v err=%v", empty, err)
	}
	for _, raw := range []string{
		"", "cdn.test", "//cdn.test", "https:cdn.test", "ftp://cdn.test", "https://",
		"https://private-user:private-password@cdn.test", "https://cdn.test/private-path",
		"https://cdn.test/?private-query", "https://cdn.test?", "https://cdn.test#private-fragment", "https://cdn.test/#",
		"https://*.cdn.test", "https://cdn.*", "https://cdn.test:0", "https://cdn.test:65536", "https://cdn.test:",
		" https://cdn.test", "https://cdn.test ", "https://cdn.test\n", "https://cdn.test\u00a0",
		`https://cdn.test\`, "https://cdn.test/%2f", "https://cdn.test\x00", "https://user@cdn.test",
		"https://invalid\xff.test",
	} {
		if got, err := assets.NormalizeOrigins([]string{raw}); err == nil || got != nil || strings.Contains(err.Error(), "private-") {
			t.Errorf("invalid origin accepted or leaked: %q got=%v err=%v", raw, got, err)
		}
		options := assets.DefaultOptions()
		options.AllowedOrigins = []string{raw}
		if got, err := assets.Extract(page, []byte(`<script src="/a.js"></script>`), options); err == nil || got.References != nil || got.ExternalOrigins != nil {
			t.Errorf("invalid origin reached extraction: %q result=%+v err=%v", raw, got, err)
		}
	}
	var many []string
	for i := 0; i < assets.MaxAllowedOrigins; i++ {
		many = append(many, fmt.Sprintf("https://cdn-%d.test", i))
	}
	if got, err := assets.NormalizeOrigins(append(append([]string{}, many...), many[0]+":443/")); err != nil || len(got) != assets.MaxAllowedOrigins {
		t.Fatalf("duplicate at origin cap rejected: %v %v", got, err)
	}
	if got, err := assets.NormalizeOrigins(append(many, "https://extra.test")); err == nil || got != nil {
		t.Fatalf("origin cap not enforced: %v %v", got, err)
	}
}

func TestAllowedAssetOriginsSelectionAndDeduplication(t *testing.T) {
	markup := `<script src="https://cdn.test/first.js?keep=1&amp;next=2#ignored"></script>
<script src="https://cdn.test:443/first.js?keep=1&amp;next=2"></script>
<script src="https://cdn.test.evil.test/no.js"></script>
<link rel=stylesheet href="/local.css">
<script src="https://sub.cdn.test/no.js"></script>
<script src="https://cdn.test:444/no.js"></script>
<script src="https://second.test/other.js"></script>
<script src="https://private-user:private-password@cdn.test/no.js"></script>
<script src="https://cdn.test/no\repair.js"></script>
<script type=application/json src="https://cdn.test/no.json"></script>
<template><script src="https://cdn.test/inert.js"></script></template>
<link rel=modulepreload href="https://cdn.test/preload.js">`
	options := assets.DefaultOptions()
	options.AllowedOrigins = []string{"https://CDN.test:00443/", "https://second.test"}
	got, err := assets.Extract(page, []byte(markup), options)
	want := []assets.Reference{
		{URL: "https://cdn.test/first.js?keep=1&next=2", Kind: assets.JavaScript},
		{URL: "https://example.test/local.css", Kind: assets.Stylesheet},
		{URL: "https://second.test/other.js", Kind: assets.JavaScript},
	}
	excluded := []assets.ExternalOrigin{
		{Origin: "https://cdn.test.evil.test", Scripts: 1},
		{Origin: "https://sub.cdn.test", Scripts: 1},
		{Origin: "https://cdn.test:444", Scripts: 1},
	}
	if err != nil || !reflect.DeepEqual(got.References, want) || !reflect.DeepEqual(got.ExternalOrigins, excluded) || got.Duplicates != 1 || got.Skipped != 6 || got.Truncated {
		t.Fatalf("selection=%+v err=%v", got, err)
	}
	for _, markup := range []string{
		`<base href="https://cdn.test/files/"><script src="app.js"></script>`,
		`<script src="app.js"></script><base href="https://cdn.test/files/">`,
	} {
		got, err := assets.Extract(page, []byte(markup), options)
		if err != nil || len(got.References) != 1 || got.References[0].URL != "https://cdn.test/files/app.js" || len(got.ExternalOrigins) != 0 {
			t.Fatalf("allowed base resolution=%+v err=%v", got, err)
		}
	}
}

func TestAllowedAssetOriginsNeverDowngradeHTTPSPages(t *testing.T) {
	for _, pageURL := range []string{"https://example.test/page", "http://example.test/page"} {
		options := assets.DefaultOptions()
		options.AllowedOrigins = []string{"http://cdn.test", "https://cdn.test"}
		got, err := assets.Extract(pageURL, []byte(`<script src="http://cdn.test/plain.js"></script><script src="https://cdn.test/secure.js"></script>`), options)
		want := []assets.Reference{{URL: "https://cdn.test/secure.js", Kind: assets.JavaScript}}
		if strings.HasPrefix(pageURL, "http:") {
			want = append([]assets.Reference{{URL: "http://cdn.test/plain.js", Kind: assets.JavaScript}}, want...)
		}
		if err != nil || !reflect.DeepEqual(got.References, want) {
			t.Fatalf("page=%s result=%+v err=%v", pageURL, got, err)
		}
		if strings.HasPrefix(pageURL, "https:") && (got.Skipped != 1 || !reflect.DeepEqual(got.ExternalOrigins, []assets.ExternalOrigin{{Origin: "http://cdn.test", Scripts: 1}})) {
			t.Fatalf("downgrade not reported as excluded: %+v", got)
		}
	}
}

func TestAllowedOriginsShareAttemptsAndDeadline(t *testing.T) {
	budget, _ := assets.BudgetForProfile("standard")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	markup := `<script src="https://cdn.test/first.js"></script><link rel=stylesheet href="/local.css">`
	for i := 0; i < 4; i++ {
		markup += fmt.Sprintf(`<script src="https://cdn.test/more-%d.js"></script>`, i)
	}
	var calls []string
	client := assetFetcher(func(gotCtx context.Context, target string, _ fetch.AssetOptions) (fetch.AssetResponse, error) {
		gotDeadline, ok := gotCtx.Deadline()
		if !ok || gotDeadline != deadline {
			t.Error("shared deadline reset")
		}
		calls = append(calls, target)
		if len(calls) == 1 {
			return fetch.AssetResponse{StatusCode: 403}, fetch.ErrAssetStatus
		}
		return fetch.AssetResponse{StatusCode: 200, Body: []byte(target)}, nil
	})
	inputs := []string{"https://CDN.test:443/"}
	got, err := assets.CollectWithOptions(ctx, client, assetPage(markup), assets.CollectionOptions{Budget: budget, AllowedOrigins: inputs})
	wantCalls := []string{"https://cdn.test/first.js", "https://example.test/local.css", "https://cdn.test/more-0.js", "https://cdn.test/more-1.js", "https://cdn.test/more-2.js"}
	if err != nil || !reflect.DeepEqual(calls, wantCalls) || got.Attempted != 5 || got.Collected != 4 || !got.Truncated || got.Status != "incomplete" || got.Reason != "reference_limit" || len(got.ExternalOrigins) != 0 || !reflect.DeepEqual(got.AllowedOrigins, []string{"https://cdn.test"}) {
		t.Fatalf("collection=%+v calls=%v err=%v", got, calls, err)
	}
	inputs[0] = "changed"
	if got.AllowedOrigins[0] != "https://cdn.test" {
		t.Fatal("configured origins alias caller input")
	}
}

func TestAllowedOriginsShareAggregateBudgetsAndCancellation(t *testing.T) {
	for _, profile := range []string{"standard", "expanded"} {
		for _, dimension := range []string{"decoded", "encoded"} {
			t.Run(profile+"/"+dimension, func(t *testing.T) {
				budget, _ := assets.BudgetForProfile(profile)
				var markup strings.Builder
				for i := 0; i < 5; i++ {
					if i%2 == 0 {
						fmt.Fprintf(&markup, `<script src="https://cdn.test/%d.js"></script>`, i)
					} else {
						fmt.Fprintf(&markup, `<script src="/local-%d.js"></script>`, i)
					}
				}
				var consumed int64
				calls := 0
				client := assetFetcher(func(_ context.Context, _ string, options fetch.AssetOptions) (fetch.AssetResponse, error) {
					calls++
					usage := fetch.BodyUsage{Decoded: options.MaxBodyBytes + 1}
					limit, cause := budget.MaxTotalDecodedBytes, fetch.ErrBodyLimit
					if dimension == "encoded" {
						usage = fetch.BodyUsage{Encoded: options.MaxEncodedBodyBytes + 1}
						limit, cause = budget.MaxTotalEncodedBytes, fetch.ErrEncodedBodyLimit
					}
					consumed += usage.Decoded + usage.Encoded
					if consumed > limit {
						t.Error("aggregate budget expanded per origin")
					}
					return fetch.AssetResponse{Usage: usage}, cause
				})
				got, err := assets.CollectWithOptions(context.Background(), client, assetPage(markup.String()), assets.CollectionOptions{Budget: budget, AllowedOrigins: []string{"https://cdn.test"}})
				wantCalls := 4
				if profile == "expanded" {
					wantCalls = 2
				}
				if err != nil || calls != wantCalls || got.Attempted != wantCalls || got.Collected != 0 || got.Usage.Decoded+got.Usage.Encoded != consumed || got.Items[wantCalls].Reason != "total_byte_limit" {
					t.Fatalf("collection=%+v calls=%d err=%v", got, calls, err)
				}
			})
		}
	}
	budget, _ := assets.BudgetForProfile("standard")
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	client := assetFetcher(func(context.Context, string, fetch.AssetOptions) (fetch.AssetResponse, error) {
		calls++
		cancel()
		return fetch.AssetResponse{Body: []byte("complete")}, nil
	})
	got, err := assets.CollectWithOptions(ctx, client, assetPage(`<script src="https://cdn.test/a.js"></script><script src="/b.js"></script>`), assets.CollectionOptions{Budget: budget, AllowedOrigins: []string{"https://cdn.test"}})
	if err != nil || calls != 1 || got.Collected != 1 || len(got.Captures) != 1 || got.Items[1].Reason != "canceled" {
		t.Fatalf("cancellation=%+v calls=%d err=%v", got, calls, err)
	}
}

func TestAllowedOriginsValidateBeforeCollectionAndSurviveSkippedScope(t *testing.T) {
	budget, _ := assets.BudgetForProfile("standard")
	client := assetFetcher(func(context.Context, string, fetch.AssetOptions) (fetch.AssetResponse, error) {
		t.Fatal("invalid/skipped configuration reached network")
		return fetch.AssetResponse{}, errors.New("unexpected request")
	})
	for _, options := range []assets.CollectionOptions{{Budget: budget, AllowedOrigins: []string{"https://private-user:private-password@cdn.test"}}, {AllowedOrigins: []string{"https://cdn.test"}}} {
		if _, err := assets.CollectWithOptions(context.Background(), client, assetPage(`<script src="/a.js"></script>`), options); err == nil || strings.Contains(err.Error(), "private-") {
			t.Fatalf("invalid configuration accepted/leaked: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, err := assets.CollectWithOptions(ctx, client, assetPage(""), assets.CollectionOptions{Budget: budget, AllowedOrigins: []string{"https://CDN.test:443"}})
	if err != nil || got.Status != "skipped" || got.Reason != "canceled" || !reflect.DeepEqual(got.AllowedOrigins, []string{"https://cdn.test"}) {
		t.Fatalf("canceled scope lost configuration: %+v err=%v", got, err)
	}
	page := assetPage("not HTML")
	page.Headers.Set("Content-Type", "application/json")
	got, err = assets.CollectWithOptions(context.Background(), client, page, assets.CollectionOptions{Budget: budget, AllowedOrigins: []string{"https://cdn.test"}})
	if err != nil || got.Status != "skipped" || got.Reason != "unsupported_page_type" || !reflect.DeepEqual(got.AllowedOrigins, []string{"https://cdn.test"}) {
		t.Fatalf("unsupported scope lost configuration: %+v err=%v", got, err)
	}
	got, err = assets.CollectWithOptions(context.Background(), client, assetPage("<p>no assets</p>"), assets.CollectionOptions{Budget: budget, AllowedOrigins: []string{"https://cdn.test"}})
	if err != nil || got.Status != "complete" || got.Attempted != 0 || len(got.Items) != 0 || !reflect.DeepEqual(got.AllowedOrigins, []string{"https://cdn.test"}) {
		t.Fatalf("unused origin caused I/O or lost scope: %+v err=%v", got, err)
	}
}
