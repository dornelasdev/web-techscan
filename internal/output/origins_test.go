package output_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/assets"
	"webscan/internal/output"
)

func TestExternalOriginReportOutputAndCopySafety(t *testing.T) {
	collection := assets.Collection{
		Budget: outputBudget(t, "standard"), Status: "complete", SkippedDeclarations: 5,
		ExternalOrigins: []assets.ExternalOrigin{
			{Origin: "https://cdn.test", Scripts: 2, Stylesheets: 1},
			{Origin: "http://[::1]:8080", Stylesheets: 1},
		},
		ExternalOriginsTruncated: true,
	}
	report := sampleReport()
	report.Assets = output.NewAssetReport(collection)
	want := []output.ExternalOrigin{
		{Origin: "https://cdn.test", Scripts: 2, Stylesheets: 1},
		{Origin: "http://[::1]:8080", Stylesheets: 1},
	}
	if !reflect.DeepEqual(report.Assets.ExternalOrigins, want) || !report.Assets.ExternalOriginsTruncated {
		t.Fatalf("origins lost during reporting: %+v", report.Assets)
	}
	collection.ExternalOrigins[0].Origin = "changed-collection"
	if !reflect.DeepEqual(report.Assets.ExternalOrigins, want) {
		t.Fatal("report shares collection metadata")
	}
	redacted := report.RedactQueries()
	if !reflect.DeepEqual(redacted.Assets.ExternalOrigins, want) || !reflect.DeepEqual(redacted.RedactQueries(), redacted) {
		t.Fatal("redaction changed origins or is not idempotent")
	}
	for _, r := range []output.Report{report, redacted} {
		var data bytes.Buffer
		if err := output.JSON(&data, r); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(data.String(), `"external_origins_truncated": true`) || !strings.Contains(data.String(), `"origin": "https://cdn.test"`) {
			t.Fatalf("missing JSON metadata: %s", &data)
		}
		var decoded output.Report
		if err := json.Unmarshal(data.Bytes(), &decoded); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(decoded, r) {
			t.Fatal("JSON round trip changed origin metadata")
		}
		for _, color := range []bool{false, true} {
			data.Reset()
			if err := output.Terminal(&data, r, color); err != nil {
				t.Fatal(err)
			}
			for _, text := range []string{
				"External asset origins skipped (not requested; declaration counts):",
				"https://cdn.test (scripts: 2, stylesheets: 1)",
				"http://[::1]:8080 (scripts: 0, stylesheets: 1)",
				"External origin list truncated; additional origins omitted.",
			} {
				if !strings.Contains(data.String(), text) {
					t.Errorf("missing %q in %s", text, &data)
				}
			}
		}
	}
	redacted.Assets.ExternalOrigins[0].Origin = "changed-copy"
	redacted.Assets.ExternalOrigins[0].Scripts = 99
	if !reflect.DeepEqual(report.Assets.ExternalOrigins, want) {
		t.Fatal("redacted report shares mutable origin metadata")
	}
}

func TestExternalOriginsEmptyArraysAndTerminalSafety(t *testing.T) {
	for _, status := range []string{"complete", "incomplete", "skipped"} {
		report := sampleReport()
		report.Assets = output.NewAssetReport(assets.Collection{Budget: outputBudget(t, "standard"), Status: status})
		var data bytes.Buffer
		if err := output.JSON(&data, report.RedactQueries()); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(data.String(), `"external_origins": []`) || !strings.Contains(data.String(), `"external_origins_truncated": false`) {
			t.Fatalf("invalid empty metadata: %s", &data)
		}
		data.Reset()
		if err := output.Terminal(&data, report, false); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(data.String(), "External asset origins") || strings.Contains(data.String(), "External origin list truncated") {
			t.Fatalf("empty discovery has a misleading heading: %s", &data)
		}
	}
	report := sampleReport()
	report.Assets = output.NewAssetReport(assets.Collection{ExternalOrigins: []assets.ExternalOrigin{{Origin: "https://unsafe\x1b\n\u202e\u2028.test", Scripts: 1}}})
	var data bytes.Buffer
	if err := output.Terminal(&data, report, false); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(data.String(), "\x1b\u202e\u2028") || !strings.Contains(data.String(), "https://unsafe����.test") {
		t.Fatalf("unsafe origin display: %q", data.String())
	}
}
