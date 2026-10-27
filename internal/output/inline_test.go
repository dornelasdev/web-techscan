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

func TestInlineCSSReportProvenancePrivacyAndCopies(t *testing.T) {
	findings := []detect.Finding{{ID: "bootstrap", Name: "Bootstrap", Category: detect.UIFramework, State: detect.Inferred, Evidence: []detect.Evidence{
		{RuleID: "asset-css-banner-and-buttons", Description: "CSS asset markers", AssetURL: "https://example.test/a.css?private-query", Signals: []detect.Signal{{Source: detect.AssetCSS}}},
		{RuleID: "inline-css-banner-and-buttons", Description: "Inline CSS markers", StyleBlock: 3, Signals: []detect.Signal{{Source: detect.InlineCSS}}},
	}}}
	report := output.NewReport(fetch.Snapshot{OriginalURL: "https://example.test/?private-page", FinalURL: "https://example.test/?private-page"}, findings, 40)
	collection := assets.Collection{Budget: outputBudget(t, "standard"), Status: "complete", InlineCSS: assets.InlineCSSCollection{
		Status: "incomplete", Reason: "block_byte_limit", Seen: 3, Collected: 2, Skipped: 1, Bytes: 8,
		Items:  []assets.InlineStyleItem{{Index: 1, Status: "collected", Bytes: 4}, {Index: 2, Status: "skipped", Reason: "block_byte_limit", Bytes: assets.MaxInlineStyleBytes + 1}, {Index: 3, Status: "collected", Bytes: 4}},
		Blocks: []assets.InlineStyle{{Index: 1, Body: []byte("private-inline-body")}},
	}}
	report.Assets = output.NewAssetReport(collection)
	redacted := report.RedactQueries()
	if !reflect.DeepEqual(redacted.RedactQueries(), redacted) || !reflect.DeepEqual(redacted.Assets.InlineCSS, report.Assets.InlineCSS) || redacted.Findings[0].Evidence[1].StyleBlock != 3 || redacted.Findings[0].Evidence[1].AssetURL != "" {
		t.Fatal("inline redaction/provenance changed")
	}
	collection.InlineCSS.Items[0].Index = 99
	findings[0].Evidence[1].StyleBlock = 99
	if report.Assets.InlineCSS.Items[0].Index != 1 || report.Findings[0].Evidence[1].StyleBlock != 3 {
		t.Fatal("report shares mutable inline inputs")
	}
	for _, r := range []output.Report{report, redacted} {
		var data bytes.Buffer
		if err := output.JSON(&data, r); err != nil {
			t.Fatal(err)
		}
		var decoded output.Report
		if err := json.Unmarshal(data.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded, r) || !strings.Contains(data.String(), `"style_block": 3`) || strings.Contains(data.String(), "private-inline-body") {
			t.Fatalf("inline JSON=%s", &data)
		}
		if r.QueryRedacted && strings.Contains(data.String(), "private-") {
			t.Fatal("query leaked alongside inline evidence")
		}
		for _, color := range []bool{false, true} {
			data.Reset()
			if err := output.Terminal(&data, r, color); err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{"Inline CSS: incomplete", "Inline style block: 3", "Style block 2: skipped (block_byte_limit)", "524288 bytes per block", "1048576 bytes combined"} {
				if !strings.Contains(data.String(), text) {
					t.Errorf("missing %q in %s", text, &data)
				}
			}
			if strings.Contains(data.String(), "Asset: inline") || strings.Contains(data.String(), "private-inline-body") {
				t.Fatal("inline CSS fabricated a URL or leaked content")
			}
		}
	}
	redacted.Assets.InlineCSS.Items[0].Index = 88
	redacted.Findings[0].Evidence[1].StyleBlock = 88
	if report.Assets.InlineCSS.Items[0].Index != 1 || report.Findings[0].Evidence[1].StyleBlock != 3 {
		t.Fatal("redacted report shares mutable inline fields")
	}
}

func TestEmptyInlineCSSReportAndDisplaySafety(t *testing.T) {
	for _, status := range []string{"complete", "skipped"} {
		report := sampleReport()
		report.Assets = output.NewAssetReport(assets.Collection{InlineCSS: assets.InlineCSSCollection{Status: status}})
		var data bytes.Buffer
		if err := output.JSON(&data, report); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(data.String(), `"inline_css": {`) || !strings.Contains(data.String(), `"items": []`) || strings.Contains(data.String(), `"style_block"`) {
			t.Fatalf("empty inline report=%s", &data)
		}
	}
	report := sampleReport()
	report.Assets = output.NewAssetReport(assets.Collection{InlineCSS: assets.InlineCSSCollection{Status: "unsafe\x1b\u202e", Reason: "unsafe\n\u2028", Items: []assets.InlineStyleItem{{Index: 1, Status: "unsafe\x1b", Reason: "unsafe\u202e"}}}})
	var data bytes.Buffer
	if err := output.Terminal(&data, report, false); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(data.String(), "\x1b\u202e\u2028") {
		t.Fatalf("unsafe inline metadata display: %q", data.String())
	}
}
