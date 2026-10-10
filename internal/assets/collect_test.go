package assets_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"webscan/internal/assets"
	"webscan/internal/fetch"
)

type assetFetcher func(context.Context, string, fetch.AssetOptions) (fetch.AssetResponse, error)

func (f assetFetcher) FetchAsset(ctx context.Context, url string, options fetch.AssetOptions) (fetch.AssetResponse, error) {
	return f(ctx, url, options)
}

func assetPage(markup string) fetch.Snapshot {
	return fetch.Snapshot{FinalURL: "https://example.test/page", Headers: http.Header{"Content-Type": {"text/html; charset=utf-8"}}, Body: []byte(markup)}
}

func TestCollectBoundedReferencesAndSeparateBodies(t *testing.T) {
	page := assetPage(`<script src="/a.js"></script><link rel="stylesheet" href="/b.css"><script src="/a.js#duplicate"></script><script src="https://other.test/no.js"></script>`)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	var urls []string
	client := assetFetcher(func(gotContext context.Context, url string, options fetch.AssetOptions) (fetch.AssetResponse, error) {
		gotDeadline, ok := gotContext.Deadline()
		if !ok || !gotDeadline.Equal(deadline) {
			t.Error("shared deadline changed")
		}
		urls = append(urls, url)
		wantTypes := []string{"text/css"}
		if len(urls) == 1 {
			wantTypes = []string{"text/javascript", "application/javascript", "text/ecmascript", "application/ecmascript"}
		}
		if !reflect.DeepEqual(options.MediaTypes, wantTypes) || options.MaxBodyBytes != assets.MaxAssetDecodedBytes || options.MaxEncodedBodyBytes != assets.MaxAssetEncodedBytes {
			t.Errorf("unexpected request options: %+v", options)
		}
		return fetch.AssetResponse{StatusCode: 200, Body: []byte(url), Usage: fetch.BodyUsage{Decoded: int64(len(url)), Encoded: int64(len(url))}}, nil
	})
	got := assets.Collect(ctx, client, page)
	if got.Status != "complete" || got.Attempted != 2 || got.Collected != 2 || got.SkippedDeclarations != 1 || got.Duplicates != 1 || len(got.Captures) != 2 || len(got.Items) != 2 {
		t.Fatalf("unexpected collection: %+v", got)
	}
	if !reflect.DeepEqual(urls, []string{"https://example.test/a.js", "https://example.test/b.css"}) {
		t.Fatalf("urls=%v", urls)
	}
	for i := range got.Captures {
		if got.Captures[i].URL != urls[i] || string(got.Captures[i].Body) != urls[i] || got.Items[i].Status != "collected" {
			t.Error("asset identity/body mixed")
		}
	}
	if got.Usage.Decoded != int64(len(urls[0])+len(urls[1])) || got.Usage.Decoded != got.Usage.Encoded {
		t.Errorf("usage=%+v", got.Usage)
	}
}

func TestCollectAttemptLimitIncludesFailures(t *testing.T) {
	var markup strings.Builder
	for i := range 9 {
		fmt.Fprintf(&markup, `<script src="/%d.js"></script>`, i)
	}
	count := 0
	client := assetFetcher(func(context.Context, string, fetch.AssetOptions) (fetch.AssetResponse, error) {
		count++
		return fetch.AssetResponse{StatusCode: 403}, fetch.ErrAssetStatus
	})
	got := assets.Collect(context.Background(), client, assetPage(markup.String()))
	if count != 5 || got.Attempted != 5 || got.Collected != 0 || len(got.Items) != 5 || !got.Truncated || got.Status != "incomplete" || got.Reason != "reference_limit" {
		t.Fatalf("got=%+v calls=%d", got, count)
	}
	for _, item := range got.Items {
		if item.Status != "failed" || item.Reason != "unsuccessful_status" || item.HTTPStatus != 403 {
			t.Errorf("item=%+v", item)
		}
	}
}

func TestCollectAggregateBudgetsIncludeFailedProbes(t *testing.T) {
	for _, dimension := range []string{"decoded", "encoded"} {
		t.Run(dimension, func(t *testing.T) {
			var markup strings.Builder
			for i := range 5 {
				fmt.Fprintf(&markup, `<script src="/%d.js"></script>`, i)
			}
			var consumed int64
			calls := 0
			client := assetFetcher(func(_ context.Context, _ string, options fetch.AssetOptions) (fetch.AssetResponse, error) {
				calls++
				usage, cause := fetch.BodyUsage{}, fetch.ErrBodyLimit
				if dimension == "decoded" {
					if options.MaxBodyBytes+1 > assets.MaxTotalDecodedBytes-consumed {
						t.Error("decoded probe exceeds aggregate")
					}
					usage.Decoded = options.MaxBodyBytes + 1
					consumed += usage.Decoded
				} else {
					if options.MaxEncodedBodyBytes+1 > assets.MaxTotalEncodedBytes-consumed {
						t.Error("encoded probe exceeds aggregate")
					}
					usage.Encoded = options.MaxEncodedBodyBytes + 1
					consumed += usage.Encoded
					cause = fetch.ErrEncodedBodyLimit
				}
				return fetch.AssetResponse{StatusCode: 200, Usage: usage}, cause
			})
			got := assets.Collect(context.Background(), client, assetPage(markup.String()))
			if calls != 4 || got.Attempted != 4 || got.Collected != 0 || got.Status != "incomplete" || got.Items[4].Status != "skipped" || got.Items[4].Reason != "total_byte_limit" {
				t.Fatalf("got=%+v calls=%d", got, calls)
			}
			if (dimension == "decoded" && got.Usage.Decoded != assets.MaxTotalDecodedBytes) || (dimension == "encoded" && got.Usage.Encoded != assets.MaxTotalEncodedBytes) {
				t.Errorf("usage=%+v", got.Usage)
			}
		})
	}
}

func TestCollectStopsOnSharedCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	calls := 0
	client := assetFetcher(func(context.Context, string, fetch.AssetOptions) (fetch.AssetResponse, error) {
		calls++
		cancel()
		return fetch.AssetResponse{Usage: fetch.BodyUsage{Decoded: 3, Encoded: 3}}, context.Canceled
	})
	got := assets.Collect(ctx, client, assetPage(`<script src="/a"></script><script src="/b"></script>`))
	if calls != 1 || got.Status != "incomplete" || got.Attempted != 1 || len(got.Items) != 2 || got.Items[0].Reason != "canceled" || got.Items[1].Status != "skipped" || got.Items[1].Reason != "canceled" || got.Usage.Decoded != 3 {
		t.Fatalf("got=%+v calls=%d", got, calls)
	}
	got = assets.Collect(ctx, client, assetPage(`<script src="/a"></script>`))
	if calls != 1 || got.Status != "skipped" || got.Reason != "canceled" || got.Items == nil || len(got.Items) != 0 {
		t.Fatalf("already canceled: %+v", got)
	}
}

func TestCollectEligibilityAndEmptyScope(t *testing.T) {
	for _, tc := range []struct{ name, contentType, body, status, reason string }{
		{"non-html", "text/plain", `<script src="/a"></script>`, "skipped", "unsupported_page_type"},
		{"xhtml", "application/xhtml+xml", `<script src="/a"></script>`, "skipped", "unsupported_page_type"},
		{"legacy-charset", "text/html; charset=windows-1252", `<script src="/a"></script>`, "skipped", "unsupported_page_type"},
		{"bad-type", "text/html; broken", "", "skipped", "unsupported_page_type"},
		{"invalid-utf8", "text/html", "<p>\xff</p>", "skipped", "invalid_utf8_html"},
		{"html-limit", "text/html", strings.Repeat(" ", 2<<20) + "x", "skipped", "html_limit"},
		{"no-references", "text/html", "<p>hello</p>", "complete", ""},
		{"only-off-origin", "text/html", `<script src="https://other.test/a.js"></script>`, "complete", ""},
		{"sniff-html", "", "<!doctype html><p>hello</p>", "complete", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			page := assetPage(tc.body)
			page.Headers.Set("Content-Type", tc.contentType)
			got := assets.Collect(context.Background(), assetFetcher(func(context.Context, string, fetch.AssetOptions) (fetch.AssetResponse, error) {
				t.Fatal("unexpected asset fetch")
				return fetch.AssetResponse{}, nil
			}), page)
			if got.Status != tc.status || got.Reason != tc.reason || got.Attempted != 0 || got.Items == nil || got.Captures == nil {
				t.Fatalf("got=%+v", got)
			}
		})
	}
}

func TestCollectFailureReasonsAreSafeAndContinue(t *testing.T) {
	for _, tc := range []struct {
		cause  error
		reason string
	}{
		{fetch.ErrAssetRedirect, "redirect_not_allowed"}, {fetch.ErrAssetMediaType, "unsuitable_content_type"},
		{fetch.ErrContentEncoding, "unsupported_content_encoding"}, {context.DeadlineExceeded, "timeout"},
		{errors.New("private-query\x1b raw Location and body"), "request_or_body_error"},
	} {
		t.Run(tc.reason, func(t *testing.T) {
			calls := 0
			got := assets.Collect(context.Background(), assetFetcher(func(context.Context, string, fetch.AssetOptions) (fetch.AssetResponse, error) {
				calls++
				if calls == 1 {
					return fetch.AssetResponse{}, tc.cause
				}
				return fetch.AssetResponse{StatusCode: 200, Body: []byte("ok"), Usage: fetch.BodyUsage{Decoded: 2, Encoded: 2}}, nil
			}), assetPage(`<script src="/a"></script><script src="/b"></script>`))
			if calls != 2 || got.Collected != 1 || got.Status != "incomplete" || got.Items[0].Reason != tc.reason || got.Items[1].Status != "collected" {
				t.Fatalf("got=%+v calls=%d", got, calls)
			}
		})
	}
}
