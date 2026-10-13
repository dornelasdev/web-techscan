package output_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/assets"
	"webscan/internal/fetch"
	"webscan/internal/output"
)

func outputBudget(t *testing.T, profile string) assets.Budget {
	t.Helper()
	budget, err := assets.BudgetForProfile(profile)
	if err != nil {
		t.Fatal(err)
	}
	return budget
}

func TestAssetBudgetMetadataCopiesAndRenders(t *testing.T) {
	for _, profile := range []string{"standard", "expanded"} {
		for _, status := range []string{"complete", "incomplete", "skipped"} {
			t.Run(profile+"/"+status, func(t *testing.T) {
				budget := outputBudget(t, profile)
				collection := assets.Collection{Budget: budget, Status: status, Items: []assets.Item{}}
				report := output.NewReport(fetch.Snapshot{OriginalURL: "https://example.test/?private-query=1", FinalURL: "https://example.test/?private-query=1"}, nil, 22)
				report.Assets = output.NewAssetReport(collection)
				want := output.AssetBudget{Profile: profile, MaxAssetDecodedBytes: budget.MaxAssetDecodedBytes, MaxAssetEncodedBytes: budget.MaxAssetEncodedBytes, MaxTotalDecodedBytes: budget.MaxTotalDecodedBytes, MaxTotalEncodedBytes: budget.MaxTotalEncodedBytes}
				if report.Assets.Budget != want {
					t.Fatalf("budget=%+v want=%+v", report.Assets.Budget, want)
				}
				redacted := report.RedactQueries()
				if redacted.Assets.Budget != want || !reflect.DeepEqual(redacted.RedactQueries(), redacted) {
					t.Error("redaction changed configured budget")
				}
				var data bytes.Buffer
				if err := output.JSON(&data, redacted); err != nil {
					t.Fatal(err)
				}
				var decoded output.Report
				if err := json.Unmarshal(data.Bytes(), &decoded); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(decoded, redacted) || strings.Contains(data.String(), "private-") {
					t.Error("JSON changed budget or leaked query")
				}
				for _, color := range []bool{false, true} {
					data.Reset()
					if err := output.Terminal(&data, redacted, color); err != nil {
						t.Fatal(err)
					}
					wantLine := fmt.Sprintf("Budget: %s; per asset %d decoded / %d encoded bytes; combined %d decoded / %d encoded bytes", profile, budget.MaxAssetDecodedBytes, budget.MaxAssetEncodedBytes, budget.MaxTotalDecodedBytes, budget.MaxTotalEncodedBytes)
					if !strings.Contains(data.String(), wantLine) || !strings.Contains(data.String(), "Assets: "+status) {
						t.Errorf("terminal budget=%s", &data)
					}
				}
				redacted.Assets.Budget.Profile = "changed"
				redacted.Assets.Budget.MaxAssetDecodedBytes = 1
				if report.Assets.Budget != want || collection.Budget != budget {
					t.Error("redacted budget shares mutable metadata")
				}
				collection.Budget.MaxAssetEncodedBytes = 1
				if report.Assets.Budget != want {
					t.Error("report shares collection budget")
				}
			})
		}
	}
}

func TestAssetBudgetProfileTerminalSafety(t *testing.T) {
	report := sampleReport()
	report.Assets = output.NewAssetReport(assets.Collection{Budget: outputBudget(t, "standard"), Status: "complete"})
	report.Assets.Budget.Profile = "standard\nforged\u202e\x1b"
	for _, color := range []bool{false, true} {
		var data bytes.Buffer
		if err := output.Terminal(&data, report, color); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(data.String(), "Budget: standard�forged��;") || strings.Contains(data.String(), "\nforged") || strings.ContainsRune(data.String(), '\u202e') {
			t.Errorf("unsafe budget display: %s", &data)
		}
	}
}
