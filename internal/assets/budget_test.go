package assets_test

import (
	"context"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"
	"time"

	"webscan/internal/assets"
	"webscan/internal/fetch"
)

func TestBudgetProfiles(t *testing.T) {
	for _, want := range []assets.Budget{
		{Profile: "standard", MaxAssetDecodedBytes: 512 << 10, MaxAssetEncodedBytes: 1 << 20, MaxTotalDecodedBytes: 2 << 20, MaxTotalEncodedBytes: 4 << 20},
		{Profile: "expanded", MaxAssetDecodedBytes: 4 << 20, MaxAssetEncodedBytes: 8 << 20, MaxTotalDecodedBytes: 8 << 20, MaxTotalEncodedBytes: 16 << 20},
	} {
		got, err := assets.BudgetForProfile(want.Profile)
		if err != nil || got != want {
			t.Fatalf("profile=%s got=%+v err=%v", want.Profile, got, err)
		}
		got.MaxAssetDecodedBytes = 1
		again, err := assets.BudgetForProfile(want.Profile)
		if err != nil || again != want {
			t.Error("profile resolver shares mutable limits")
		}
	}
	for _, name := range []string{"", "Expanded", " expanded", "standard ", "unlimited", "0", "private-query\x1b"} {
		budget, err := assets.BudgetForProfile(name)
		if err == nil || budget != (assets.Budget{}) || strings.Contains(err.Error(), name) && strings.Contains(name, "private-") {
			t.Errorf("invalid profile=%q budget=%+v err=%v", name, budget, err)
		}
	}
}

func TestCollectRejectsAlteredBudgetsBeforeIO(t *testing.T) {
	budget, err := assets.BudgetForProfile("expanded")
	if err != nil {
		t.Fatal(err)
	}
	invalid := []assets.Budget{{}, {Profile: "unknown"}}
	for _, value := range []int64{-1, 0, 1, math.MaxInt64} {
		for field := 0; field < 4; field++ {
			bad := budget
			switch field {
			case 0:
				bad.MaxAssetDecodedBytes = value
			case 1:
				bad.MaxAssetEncodedBytes = value
			case 2:
				bad.MaxTotalDecodedBytes = value
			case 3:
				bad.MaxTotalEncodedBytes = value
			}
			invalid = append(invalid, bad)
		}
	}
	client := assetFetcher(func(context.Context, string, fetch.AssetOptions) (fetch.AssetResponse, error) {
		t.Fatal("invalid budget reached fetcher")
		return fetch.AssetResponse{}, nil
	})
	for _, bad := range invalid {
		if _, err := assets.CollectWithBudget(context.Background(), client, assetPage(`<script src="/file"></script>`), bad); err == nil {
			t.Errorf("accepted invalid budget=%+v", bad)
		}
	}
}

func TestStandardCollectionParity(t *testing.T) {
	budget, err := assets.BudgetForProfile("standard")
	if err != nil {
		t.Fatal(err)
	}
	client := assetFetcher(func(_ context.Context, url string, _ fetch.AssetOptions) (fetch.AssetResponse, error) {
		return fetch.AssetResponse{StatusCode: 200, Body: []byte(url), Usage: fetch.BodyUsage{Decoded: int64(len(url)), Encoded: int64(len(url))}}, nil
	})
	page := assetPage(`<script src="/file"></script><link rel="stylesheet" href="/style">`)
	implicit := assets.Collect(context.Background(), client, page)
	explicit, err := assets.CollectWithBudget(context.Background(), client, page, budget)
	if err != nil || !reflect.DeepEqual(implicit, explicit) || explicit.Budget != budget {
		t.Fatalf("standard parity: implicit=%+v explicit=%+v err=%v", implicit, explicit, err)
	}
}

func TestProfileAggregateBudgetsIncludeFailedProbes(t *testing.T) {
	for _, profile := range []string{"standard", "expanded"} {
		budget, err := assets.BudgetForProfile(profile)
		if err != nil {
			t.Fatal(err)
		}
		for _, dimension := range []string{"decoded", "encoded"} {
			t.Run(profile+"/"+dimension, func(t *testing.T) {
				var markup strings.Builder
				for i := range assets.MaxAttempts {
					fmt.Fprintf(&markup, `<script src="/%d"></script>`, i)
				}
				perAsset, total := budget.MaxAssetDecodedBytes, budget.MaxTotalDecodedBytes
				if dimension == "encoded" {
					perAsset, total = budget.MaxAssetEncodedBytes, budget.MaxTotalEncodedBytes
				}
				var consumed int64
				calls := 0
				client := assetFetcher(func(_ context.Context, _ string, options fetch.AssetOptions) (fetch.AssetResponse, error) {
					limit := options.MaxBodyBytes
					usage, cause := fetch.BodyUsage{}, fetch.ErrBodyLimit
					if dimension == "encoded" {
						limit, cause = options.MaxEncodedBodyBytes, fetch.ErrEncodedBodyLimit
					}
					if limit != min(perAsset, total-consumed-1) || limit+1 > total-consumed {
						t.Errorf("limit=%d remaining=%d", limit, total-consumed)
					}
					consumed += limit + 1
					calls++
					if dimension == "decoded" {
						usage.Decoded = limit + 1
					} else {
						usage.Encoded = limit + 1
					}
					return fetch.AssetResponse{StatusCode: 200, Usage: usage}, cause
				})
				got, err := assets.CollectWithBudget(context.Background(), client, assetPage(markup.String()), budget)
				if err != nil || got.Budget != budget || got.Status != "incomplete" || got.Attempted != int(total/perAsset) || got.Attempted != calls || got.Collected != 0 || consumed != total || len(got.Captures) != 0 || len(got.Items) != assets.MaxAttempts {
					t.Fatalf("collection=%+v consumed=%d err=%v", got, consumed, err)
				}
				for _, item := range got.Items[calls:] {
					if item.Status != "skipped" || item.Reason != "total_byte_limit" {
						t.Errorf("exhausted budget item=%+v", item)
					}
				}
			})
		}
	}
}

func TestExpandedCollectionPreservesPoliciesAndSkipMetadata(t *testing.T) {
	budget, err := assets.BudgetForProfile("expanded")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	var markup strings.Builder
	markup.WriteString(`<script src="https://other.test/excluded"></script>`)
	for i := range 7 {
		fmt.Fprintf(&markup, `<script src="/%d"></script>`, i)
	}
	calls := 0
	client := assetFetcher(func(gotContext context.Context, url string, options fetch.AssetOptions) (fetch.AssetResponse, error) {
		gotDeadline, _ := gotContext.Deadline()
		if !gotDeadline.Equal(deadline) || url != fmt.Sprintf("https://example.test/%d", calls) || options.MaxBodyBytes != budget.MaxAssetDecodedBytes || options.MaxEncodedBodyBytes != budget.MaxAssetEncodedBytes {
			t.Errorf("collection policy/options changed: url=%s options=%+v", url, options)
		}
		calls++
		return fetch.AssetResponse{StatusCode: 403}, fetch.ErrAssetStatus
	})
	got, err := assets.CollectWithBudget(ctx, client, assetPage(markup.String()), budget)
	if err != nil || calls != assets.MaxAttempts || got.Budget != budget || !got.Truncated || got.SkippedDeclarations != 1 || got.Reason != "reference_limit" {
		t.Fatalf("collection=%+v calls=%d err=%v", got, calls, err)
	}
	cancel()
	got, err = assets.CollectWithBudget(ctx, client, assetPage(`<script src="/file"></script>`), budget)
	if err != nil || got.Budget != budget || got.Status != "skipped" || got.Reason != "canceled" || calls != assets.MaxAttempts {
		t.Fatalf("canceled collection=%+v err=%v", got, err)
	}
	page := assetPage(`<script src="/file"></script>`)
	page.Headers.Set("Content-Type", "text/plain")
	got, err = assets.CollectWithBudget(context.Background(), client, page, budget)
	if err != nil || got.Budget != budget || got.Reason != "unsupported_page_type" || calls != assets.MaxAttempts {
		t.Fatalf("unsupported page collection=%+v err=%v", got, err)
	}
}

func TestExpandedBudgetFailurePreservesEarlierCapture(t *testing.T) {
	budget, err := assets.BudgetForProfile("expanded")
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	client := assetFetcher(func(_ context.Context, _ string, options fetch.AssetOptions) (fetch.AssetResponse, error) {
		calls++
		if calls == 1 {
			if options.MaxBodyBytes != budget.MaxAssetDecodedBytes {
				t.Errorf("initial decoded cap=%d", options.MaxBodyBytes)
			}
			body := []byte(strings.Repeat("x", int(options.MaxBodyBytes)))
			return fetch.AssetResponse{StatusCode: 200, Body: body, Usage: fetch.BodyUsage{Decoded: int64(len(body)), Encoded: 100}}, nil
		}
		if options.MaxBodyBytes != budget.MaxAssetDecodedBytes-1 {
			t.Errorf("aggregate clamp=%d", options.MaxBodyBytes)
		}
		return fetch.AssetResponse{StatusCode: 200, Usage: fetch.BodyUsage{Decoded: options.MaxBodyBytes + 1, Encoded: 100}}, fetch.ErrBodyLimit
	})
	got, err := assets.CollectWithBudget(context.Background(), client, assetPage(`<script src="/first"></script><script src="/failed"></script><script src="/skipped"></script>`), budget)
	if err != nil || calls != 2 || got.Collected != 1 || len(got.Captures) != 1 || got.Captures[0].URL != "https://example.test/first" || int64(len(got.Captures[0].Body)) != budget.MaxAssetDecodedBytes || got.Usage.Decoded != budget.MaxTotalDecodedBytes || got.Items[1].Reason != "decoded_body_limit" || got.Items[2].Reason != "total_byte_limit" {
		t.Fatalf("earlier capture/budget accounting=%+v err=%v", got, err)
	}
}

func TestExpandedStylesheetBudget(t *testing.T) {
	budget, err := assets.BudgetForProfile("expanded")
	if err != nil {
		t.Fatal(err)
	}
	client := assetFetcher(func(_ context.Context, _ string, options fetch.AssetOptions) (fetch.AssetResponse, error) {
		if options.MaxBodyBytes != budget.MaxAssetDecodedBytes || options.MaxEncodedBodyBytes != budget.MaxAssetEncodedBytes || !reflect.DeepEqual(options.MediaTypes, []string{"text/css"}) {
			t.Errorf("stylesheet options=%+v", options)
		}
		return fetch.AssetResponse{StatusCode: 200, Body: []byte("a{}"), Usage: fetch.BodyUsage{Decoded: 3, Encoded: 3}}, nil
	})
	got, err := assets.CollectWithBudget(context.Background(), client, assetPage(`<link rel="stylesheet" href="/style">`), budget)
	if err != nil || got.Budget != budget || got.Collected != 1 || len(got.Captures) != 1 || got.Captures[0].Kind != assets.Stylesheet {
		t.Fatalf("stylesheet collection=%+v err=%v", got, err)
	}
}
