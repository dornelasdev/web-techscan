package output_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/assets"
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
			if !strings.Contains(data.String(), "Assets: incomplete") || !strings.Contains(data.String(), "Collection only") {
				t.Error("missing coverage/collection-only warning")
			}
		}
	}
	redacted.Assets.Items[0].URL = "changed"
	redacted.Assets.Status = "changed"
	if report.Assets.Items[0].URL != url || report.Assets.Status != "incomplete" {
		t.Error("report shares mutable redaction metadata")
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
		if !strings.Contains(data.String(), `"items": []`) || !strings.Contains(data.String(), `"mode": "collection_only"`) {
			t.Fatalf("invalid empty assets: %s", &data)
		}
	}
}
