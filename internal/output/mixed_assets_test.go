package output_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/assets"
	"webscan/internal/detect"
	"webscan/internal/fetch"
	"webscan/internal/output"
)

func TestMixedAssetRedactionCopiesAllProvenance(t *testing.T) {
	cssURL := "https://example.test/style%3Fname?private-css=1"
	jsURL := "https://example.test/script?private-js=1"
	findings := []detect.Finding{
		{ID: "bootstrap", Name: "Bootstrap", Category: detect.UIFramework, State: detect.Inferred,
			Evidence: []detect.Evidence{{RuleID: "asset-css-banner-and-buttons", Description: "CSS evidence", AssetURL: cssURL, Signals: []detect.Signal{{Source: detect.AssetCSS}}}}},
		{ID: "nextjs", Name: "Next.js", Category: detect.Framework, State: detect.Detected,
			Evidence: []detect.Evidence{
				{RuleID: "asset-build-manifest", Description: "JS evidence", AssetURL: jsURL, Signals: []detect.Signal{{Source: detect.AssetJavaScript}}},
				{RuleID: "powered-by-header", Description: "Page evidence", Signals: []detect.Signal{{Source: detect.Header, Name: "X-Powered-By"}}},
			}},
	}
	report := output.NewReport(fetch.Snapshot{OriginalURL: "https://example.test/", FinalURL: "https://example.test/"}, findings, 19)
	report.Assets = output.NewAssetReport(assets.Collection{Status: "complete", Attempted: 2, Collected: 2, Items: []assets.Item{
		{Reference: assets.Reference{URL: cssURL, Kind: assets.Stylesheet}, Status: "collected"},
		{Reference: assets.Reference{URL: jsURL, Kind: assets.JavaScript}, Status: "collected"},
	}})
	before, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	redacted := report.RedactQueries()
	wantURLs := []string{"https://example.test/style%3Fname?[redacted]", "https://example.test/script?[redacted]"}
	for i, want := range wantURLs {
		if redacted.Findings[i].Evidence[0].AssetURL != want || redacted.Assets.Items[i].URL != want {
			t.Fatalf("redacted report=%+v", redacted)
		}
	}
	if redacted.Findings[1].Evidence[1].AssetURL != "" || redacted.Findings[1].State != "detected" || redacted.Findings[0].State != "inferred" || !reflect.DeepEqual(redacted.RedactQueries(), redacted) {
		t.Fatal("redaction changed page evidence/states or was not idempotent")
	}
	var encoded bytes.Buffer
	if err := output.JSON(&encoded, redacted); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded.String(), "private-") {
		t.Fatal("query leaked")
	}
	var decoded output.Report
	if err := json.Unmarshal(encoded.Bytes(), &decoded); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(decoded, redacted) {
		t.Fatal("round trip changed provenance")
	}
	// Mutate the copied URL-bearing records, including the page-only evidence
	// record. Signal slices are unchanged by redaction and need not be cloned.
	for i := range redacted.Findings {
		for j := range redacted.Findings[i].Evidence {
			redacted.Findings[i].Evidence[j].AssetURL = "changed"
		}
		redacted.Assets.Items[i].URL = "changed"
	}
	after, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || findings[0].Evidence[0].AssetURL != cssURL || findings[1].Evidence[0].AssetURL != jsURL {
		t.Fatal("redaction shares source provenance")
	}
}
