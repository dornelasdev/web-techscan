package output_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"

	"webscan/internal/output"
)

func reportWithDisplayText(value string) output.Report {
	report := sampleReport()
	report.FinalURL = "https://example.test/?q=" + value
	report.Findings[0].Name = value
	report.Findings[0].Category = value
	report.Findings[0].Evidence[0].Description = value
	return report
}

func TestUnicodeDisplayControls(t *testing.T) {
	// Explicit list keeps expectations independent of the production predicate.
	for _, r := range []rune{
		'\x00', '\t', '\n', '\r', '\x1b', '\x7f', '\u0085', '\u009b',
		'\u061c', '\u200e', '\u200f',
		'\u202a', '\u202b', '\u202c', '\u202d', '\u202e',
		'\u2066', '\u2067', '\u2068', '\u2069', '\u2028', '\u2029',
	} {
		t.Run(fmt.Sprintf("U+%04X", r), func(t *testing.T) {
			raw := "before" + string(r) + "after"
			report := reportWithDisplayText(raw)
			clean := reportWithDisplayText("before�after")
			var original bytes.Buffer
			if err := output.JSON(&original, report); err != nil {
				t.Fatal(err)
			}
			for _, color := range []bool{false, true} {
				var got, want bytes.Buffer
				if err := output.Terminal(&got, report, color); err != nil {
					t.Fatal(err)
				}
				if err := output.Terminal(&want, clean, color); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got.Bytes(), want.Bytes()) {
					t.Errorf("color=%t got=%q want=%q", color, got.String(), want.String())
				}
			}
			var after bytes.Buffer
			if err := output.JSON(&after, report); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(original.Bytes(), after.Bytes()) {
				t.Error("terminal rendering mutated report values")
			}
			var decoded output.Report
			if err := json.Unmarshal(after.Bytes(), &decoded); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decoded, reportWithDisplayText(raw)) {
				t.Errorf("JSON did not preserve original values: %#v", decoded)
			}

			catalog := output.CatalogReport{SchemaVersion: 1, CatalogSize: 1,
				Technologies: []output.Technology{{ID: "example", Name: raw, Category: raw}}}
			var terminal, data bytes.Buffer
			if err := output.CatalogTerminal(&terminal, catalog); err != nil {
				t.Fatal(err)
			}
			want := "Supported technologies (1)\n\nbefore�after\n  before�after\n\nCoverage depends on exposed signals; identification is not guaranteed.\n"
			if terminal.String() != want {
				t.Errorf("catalog=%q want=%q", terminal.String(), want)
			}
			if err := output.CatalogJSON(&data, catalog); err != nil {
				t.Fatal(err)
			}
			var decodedCatalog output.CatalogReport
			if err := json.Unmarshal(data.Bytes(), &decodedCatalog); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(decodedCatalog, catalog) || catalog.Technologies[0].Name != raw || catalog.Technologies[0].Category != raw {
				t.Error("catalog values changed")
			}
		})
	}
}

func TestOrdinaryUnicodeDisplayTextIsPreserved(t *testing.T) {
	for _, value := range []string{
		"café / cafe\u0301 / Ελληνικά / 日本語 / العربية / עברית",
		"emoji: 👩\u200d💻 / ✈\ufe0f / joiner: a\u200cb / nonbreaking: a\u00a0b",
		`literal escapes: %E2%80%AE / \u202e / ASCII ✓ ?`,
	} {
		var terminal bytes.Buffer
		report := reportWithDisplayText(value)
		if err := output.Terminal(&terminal, report, false); err != nil {
			t.Fatal(err)
		}
		want := "URL: https://example.test/?q=" + value + "\nHTTP status: 200\nRedirects: 1\nBody: 11 bytes\n\n" +
			"✓ " + value + " [" + value + "]\n  - " + value + "\n" +
			"? PHP [language]\n  - Inferred from Laravel\n\n✓ Detected  ? Inferred\n"
		if terminal.String() != want {
			t.Errorf("got=%q want=%q", terminal.String(), want)
		}
	}
}
