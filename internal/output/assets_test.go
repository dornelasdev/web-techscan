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

func TestAssetReportRedactionSafetyAndNoBodies(t *testing.T) {
	url := "https://example.test/a%3Fb?private-query=café\u202e\u2028"
	collection := assets.Collection{Status: "incomplete", Attempted: 1, Collected: 1,
		Items: []assets.Item{
			{Reference: assets.Reference{URL: url, Kind: assets.JavaScript}, Status: "collected", HTTPStatus: 200, Usage: fetch.BodyUsage{Decoded: 4, Encoded: 4}},
			{Reference: assets.Reference{URL: "https://example.test/b?private-skipped", Kind: assets.Stylesheet}, Status: "skipped", Reason: "timeout"},
		}, Captures: []assets.Capture{{Reference: assets.Reference{URL: url}, Body: []byte("private-body")}},
	}
	report := sampleReport()
	report.Assets = output.NewAssetReport(collection)
	redacted := report.RedactQueries()
	if redacted.Assets.Items[0].URL != "https://example.test/a%3Fb?[redacted]" || redacted.Assets.Items[1].URL != "https://example.test/b?[redacted]" || report.Assets.Items[0].URL != url || collection.Items[0].URL != url {
		t.Fatal("redaction leaked or mutated source URLs")
	}
	if !reflect.DeepEqual(redacted.RedactQueries(), redacted) {
		t.Fatal("redaction not idempotent")
	}
	for _, r := range []output.Report{report, redacted} {
		var data bytes.Buffer
		if err := output.JSON(&data, r); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(data.String(), "private-body") {
			t.Fatal("asset body included in report")
		}
		var decoded output.Report
		if err := json.Unmarshal(data.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(r, decoded) {
			t.Error("JSON round trip changed metadata")
		}
		if r.QueryRedacted && strings.Contains(data.String(), "private-") {
			t.Fatal("query leaked in JSON")
		}
		for _, color := range []bool{false, true} {
			data.Reset()
			if err := output.Terminal(&data, r, color); err != nil {
				t.Fatal(err)
			}
			if strings.ContainsAny(data.String(), "\u202e\u2028") || strings.Contains(data.String(), "private-body") {
				t.Fatal("unsafe asset terminal output")
			}
			if r.QueryRedacted && strings.Contains(data.String(), "private-") {
				t.Fatal("query leaked in terminal output")
			}
			if !strings.Contains(data.String(), "Assets: incomplete") || !strings.Contains(data.String(), "scripts are not executed") {
				t.Error("missing coverage/inspection note")
			}
		}
	}
	redacted.Assets.Items[0].URL = "changed"
	redacted.Assets.Status = "changed"
	if report.Assets.Items[0].URL != url || report.Assets.Status != "incomplete" {
		t.Error("report shares mutable redaction metadata")
	}
}

func TestAssetEvidenceURLRedactionAndCopy(t *testing.T) {
	for _, url := range []string{"https://example.test/a%3Fb?private-token=1", "https://example.test/a?", "https://example.test/a?private-key=café\u202e\u2028\u001b", "https://example.test/a"} {
		findings := []detect.Finding{{ID: "nextjs", Name: "Next.js", State: detect.Inferred, Category: detect.Framework,
			Evidence: []detect.Evidence{{RuleID: "asset-build-manifest", Description: "Synthetic asset markers", AssetURL: url, Signals: []detect.Signal{{Source: detect.AssetJavaScript}}}},
		}}
		report := output.NewReport(fetch.Snapshot{OriginalURL: "https://example.test/", FinalURL: "https://example.test/"}, findings, 18)
		redacted := report.RedactQueries()
		want, _, hasQuery := strings.Cut(url, "?")
		if hasQuery {
			want += "?[redacted]"
		}
		if redacted.Findings[0].Evidence[0].AssetURL != want || report.Findings[0].Evidence[0].AssetURL != url || findings[0].Evidence[0].AssetURL != url {
			t.Fatal("asset evidence redaction leaked/mutated")
		}
		if !reflect.DeepEqual(redacted.RedactQueries(), redacted) {
			t.Error("evidence redaction not idempotent")
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
			if !reflect.DeepEqual(r, decoded) {
				t.Error("asset evidence JSON round trip changed")
			}
			if r.QueryRedacted && strings.Contains(data.String(), "private-") {
				t.Error("query leaked through evidence JSON")
			}
			for _, color := range []bool{false, true} {
				data.Reset()
				if err := output.Terminal(&data, r, color); err != nil {
					t.Fatal(err)
				}
				if strings.ContainsAny(data.String(), "\u202e\u2028") || strings.Contains(data.String(), "\x1b\n") {
					t.Error("unsafe asset evidence URL display")
				}
				if r.QueryRedacted && (!strings.Contains(data.String(), "Asset: "+want+"\n") || strings.Contains(data.String(), "private-")) {
					t.Fatal("redacted terminal evidence mismatch")
				}
			}
		}
		redacted.Findings[0].Evidence[0].AssetURL = "changed"
		if report.Findings[0].Evidence[0].AssetURL != url {
			t.Error("redaction shares mutable evidence")
		}
		findings[0].Evidence[0].AssetURL = "changed"
		if report.Findings[0].Evidence[0].AssetURL != url {
			t.Error("report shares detector evidence")
		}
	}
}

func TestEmptyAssetReportArrayAndDefaultOmission(t *testing.T) {
	report := sampleReport()
	var data bytes.Buffer
	if err := output.JSON(&data, report); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(data.String(), `"assets"`) {
		t.Fatal("default report gained assets")
	}
	report.Assets = output.NewAssetReport(assets.Collection{Status: "complete"})
	for _, r := range []output.Report{report, report.RedactQueries()} {
		data.Reset()
		if err := output.JSON(&data, r); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(data.String(), `"items": []`) || !strings.Contains(data.String(), `"mode": "fingerprint_inspection"`) {
			t.Fatalf("invalid empty assets: %s", &data)
		}
	}
}
