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

func TestAllowedOriginReportScopeAndCopies(t *testing.T) {
	for _, status := range []string{"complete", "incomplete", "skipped"} {
		collection := assets.Collection{
			Budget: outputBudget(t, "standard"), Status: status,
			AllowedOrigins:  []string{"https://cdn.test", "http://localhost:8080"},
			ExternalOrigins: []assets.ExternalOrigin{{Origin: "https://excluded.test", Scripts: 2}},
		}
		report := sampleReport()
		report.Assets = output.NewAssetReport(collection)
		want := []string{"https://cdn.test", "http://localhost:8080"}
		collection.AllowedOrigins[0] = "changed-collection"
		redacted := report.RedactQueries()
		if !reflect.DeepEqual(report.Assets.AllowedOrigins, want) || !reflect.DeepEqual(redacted.Assets.AllowedOrigins, want) || !reflect.DeepEqual(redacted.RedactQueries(), redacted) {
			t.Fatal("scope copied incorrectly or redaction is not idempotent")
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
			if !reflect.DeepEqual(decoded, r) {
				t.Fatal("JSON scope round trip changed")
			}
			for _, color := range []bool{false, true} {
				data.Reset()
				if err := output.Terminal(&data, r, color); err != nil {
					t.Fatal(err)
				}
				for _, text := range []string{"direct same-origin and allowed-origin scope", "Allowed asset origins (configured; references only):", "https://cdn.test\n", "http://localhost:8080\n", "https://excluded.test (scripts: 2, stylesheets: 0)", "HTTP assets from HTTPS pages remain excluded."} {
					if !strings.Contains(data.String(), text) {
						t.Errorf("missing %q in %s", text, &data)
					}
				}
			}
		}
		redacted.Assets.AllowedOrigins[0] = "changed-redacted"
		if !reflect.DeepEqual(report.Assets.AllowedOrigins, want) {
			t.Fatal("redaction shares mutable scope slice")
		}
	}
}

func TestAllowedOriginEmptyScopeAndTerminalSafety(t *testing.T) {
	report := sampleReport()
	report.Assets = output.NewAssetReport(assets.Collection{Budget: outputBudget(t, "standard"), Status: "complete"})
	var data bytes.Buffer
	if err := output.JSON(&data, report.RedactQueries()); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(data.String(), `"allowed_origins": []`) {
		t.Fatalf("empty scope is not an array: %s", &data)
	}
	data.Reset()
	if err := output.Terminal(&data, report, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(data.String(), "direct same-origin scope") || strings.Contains(data.String(), "Allowed asset origins") {
		t.Fatalf("default scope changed: %s", &data)
	}
	report.Assets.AllowedOrigins = []string{"https://unsafe\x1b\n\u202e\u2028.test"}
	data.Reset()
	if err := output.Terminal(&data, report, false); err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(data.String(), "\x1b\u202e\u2028") || !strings.Contains(data.String(), "https://unsafe����.test") {
		t.Fatalf("unsafe allowed origin: %q", data.String())
	}
}
