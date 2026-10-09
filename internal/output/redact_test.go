package output_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/fetch"
	"webscan/internal/output"
)

func TestReportQueryRedaction(t *testing.T) {
	for _, tc := range []struct{ name, raw, want string }{
		{"no-query", "https://example.test/path", "https://example.test/path"},
		{"empty-query", "https://example.test/path?", "https://example.test/path?[redacted]"},
		{"keys-and-values", "https://example.test/?private-key=private-value&other=x", "https://example.test/?[redacted]"},
		{"repeated-and-bare", "https://example.test/?private-key=a&private-key=b&private-bare", "https://example.test/?[redacted]"},
		{"extra-delimiters", "https://example.test/?private-key=a?b;c&&", "https://example.test/?[redacted]"},
		{"encoded-query", "https://example.test/?%70rivate-key=%E2%80%AE+secret", "https://example.test/?[redacted]"},
		{"invalid-query-escape", "https://example.test/?private-key=%zz", "https://example.test/?[redacted]"},
		{"unicode-query", "https://example.test/?private-key=café\u202e\u2028", "https://example.test/?[redacted]"},
		{"escaped-path", "https://example.test/a%3fb%23c?private-key=secret", "https://example.test/a%3fb%23c?[redacted]"},
		{"escaped-path-only", "https://example.test/a%3Fb%23c", "https://example.test/a%3Fb%23c"},
		{"ipv6", "http://[::1]:8080/?private-key=x", "http://[::1]:8080/?[redacted]"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			snapshot := fetch.Snapshot{OriginalURL: tc.raw, FinalURL: tc.raw,
				Redirects: []fetch.Redirect{{FromURL: tc.raw, ToURL: tc.raw, StatusCode: 302}}}
			report := output.NewReport(snapshot, nil, 18)
			redacted := report.RedactQueries()
			if !redacted.QueryRedacted || redacted.URL != tc.want || redacted.FinalURL != tc.want || redacted.Redirects[0].FromURL != tc.want || redacted.Redirects[0].ToURL != tc.want {
				t.Fatalf("unexpected redacted URLs: %#v", redacted)
			}
			if !reflect.DeepEqual(redacted.RedactQueries(), redacted) {
				t.Error("redaction is not idempotent")
			}
			var data bytes.Buffer
			if err := output.JSON(&data, redacted); err != nil {
				t.Fatal(err)
			}
			var decoded output.Report
			if err := json.Unmarshal(data.Bytes(), &decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, redacted) || !strings.Contains(data.String(), `"query_redacted": true`) {
				t.Error("redacted JSON contract mismatch")
			}
			redacted.Redirects[0].ToURL = "changed"
			if report.QueryRedacted || report.URL != tc.raw || report.FinalURL != tc.raw || report.Redirects[0].FromURL != tc.raw || report.Redirects[0].ToURL != tc.raw || snapshot.Redirects[0].ToURL != tc.raw || snapshot.OriginalURL != tc.raw || snapshot.FinalURL != tc.raw {
				t.Error("redaction mutated its source report or snapshot")
			}
		})
	}
}

func TestQueryRedactionPreservesReportDataAndEmptyArrays(t *testing.T) {
	report := sampleReport()
	report.FinalURL += "?private-key=private-value"
	redacted := report.RedactQueries()
	want := sampleReport()
	want.FinalURL += "?[redacted]"
	want.QueryRedacted = true
	if !reflect.DeepEqual(redacted, want) {
		t.Errorf("redaction changed non-URL report data: %#v", redacted)
	}
	for _, color := range []bool{false, true} {
		var out bytes.Buffer
		if err := output.Terminal(&out, redacted, color); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out.String(), "URL: https://example.test/?[redacted]\n") || !strings.Contains(out.String(), "Query strings redacted in this report.\n") || strings.Contains(out.String(), "private-") {
			t.Errorf("unexpected terminal report: %q", out.String())
		}
	}
	empty := output.NewReport(fetch.Snapshot{OriginalURL: "http://example.test/", FinalURL: "http://example.test/"}, nil, 18).RedactQueries()
	var data bytes.Buffer
	if err := output.JSON(&data, empty); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{`"query_redacted": true`, `"redirects": []`, `"findings": []`} {
		if !strings.Contains(data.String(), field) {
			t.Errorf("missing %s in %s", field, &data)
		}
	}
}
