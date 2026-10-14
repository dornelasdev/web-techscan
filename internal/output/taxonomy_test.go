package output_test

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
	"webscan/internal/fetch"
	"webscan/internal/output"
)

func TestCatalogTaxonomyOrderingAndUnknownCategories(t *testing.T) {
	items := []detect.TechnologyInfo{
		{ID: "unknown-z", Name: "Last", Category: "z_future"},
		{ID: "waf", Name: "WAF", Category: detect.WAF},
		{ID: "lb", Name: "LB", Category: detect.LoadBalancer},
		{ID: "cdn", Name: "CDN", Category: detect.CDN},
		{ID: "server", Name: "Server", Category: detect.WebServer},
		{ID: "language", Name: "Language", Category: detect.Language},
		{ID: "cms", Name: "CMS", Category: detect.CMS},
		{ID: "ui", Name: "UI", Category: detect.UIFramework},
		{ID: "js-z", Name: "same", Category: detect.JSFramework},
		{ID: "js-a", Name: "Same", Category: detect.JSFramework},
		{ID: "framework", Name: "Framework", Category: detect.Framework},
		{ID: "unknown-a", Name: "First", Category: "a_future"},
	}
	report := output.NewCatalogReport(items)
	var ids []string
	for _, tech := range report.Technologies {
		ids = append(ids, tech.ID)
	}
	wantIDs := []string{"framework", "js-a", "js-z", "ui", "cms", "language", "server", "cdn", "lb", "waf", "unknown-a", "unknown-z"}
	if !reflect.DeepEqual(ids, wantIDs) {
		t.Fatalf("catalog order=%v want=%v", ids, wantIDs)
	}
	for i, j := 0, len(items)-1; i < j; i, j = i+1, j-1 {
		items[i], items[j] = items[j], items[i]
	}
	if !reflect.DeepEqual(report, output.NewCatalogReport(items)) {
		t.Fatal("input order must not change the catalog")
	}
	var terminal bytes.Buffer
	if err := output.CatalogTerminal(&terminal, report); err != nil {
		t.Fatal(err)
	}
	for _, group := range []string{"Web development", "Infrastructure", "Other"} {
		if strings.Count(terminal.String(), "\n"+group+"\n") != 1 {
			t.Errorf("missing or repeated %s group: %s", group, &terminal)
		}
	}
	if !strings.Contains(terminal.String(), "  a_future\n    First\n  z_future\n    Last\n") {
		t.Errorf("unknown categories must remain visible: %s", &terminal)
	}
	terminal.Reset()
	if err := output.CatalogTerminal(&terminal, output.NewCatalogReport(items[:0])); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(terminal.String(), "Web development") || strings.Contains(terminal.String(), "Infrastructure") || strings.Contains(terminal.String(), "Other") {
		t.Errorf("empty catalog must not emit organization headings: %s", &terminal)
	}
}

func TestScanTaxonomyPreservesJSONAndEvidence(t *testing.T) {
	findings := []detect.Finding{
		{ID: "angular", Name: "Angular", Category: detect.JSFramework, State: detect.Inferred,
			Evidence: []detect.Evidence{{RuleID: "server-host-attributes", Description: "Paired HTML indicators", Signals: []detect.Signal{{Source: detect.HTML}}}}},
		{ID: "nuxt", Name: "Nuxt", Category: detect.Framework, State: detect.Detected,
			Evidence: []detect.Evidence{{RuleID: "powered-by-header", Description: "Identifying header", Signals: []detect.Signal{{Source: detect.Header, Name: "X-Powered-By"}}}}},
	}
	report := output.NewReport(fetch.Snapshot{FinalURL: "https://example.test/"}, findings, 22)
	var data bytes.Buffer
	if err := output.JSON(&data, report); err != nil {
		t.Fatal(err)
	}
	var raw struct {
		SchemaVersion int                          `json:"schema_version"`
		Findings      []map[string]json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal(data.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw.SchemaVersion != 1 || len(raw.Findings) != 2 {
		t.Fatalf("unexpected report contract: %s", &data)
	}
	for _, finding := range raw.Findings {
		if len(finding) != 5 || finding["id"] == nil || finding["name"] == nil || finding["category"] == nil || finding["state"] == nil || finding["evidence"] == nil {
			t.Fatalf("unexpected finding fields: %v", finding)
		}
	}
	for _, color := range []bool{false, true} {
		var terminal bytes.Buffer
		if err := output.Terminal(&terminal, report, color); err != nil {
			t.Fatal(err)
		}
		text := strings.NewReplacer("\x1b[33m", "", "\x1b[32m", "", "\x1b[0m", "").Replace(terminal.String())
		if !strings.Contains(text, "? Angular [JavaScript framework]") || !strings.Contains(text, "✓ Nuxt [framework]") || strings.Contains(text, "Web development") || strings.Contains(text, "Infrastructure") {
			t.Errorf("unexpected scan taxonomy: %s", text)
		}
	}
	var after bytes.Buffer
	if err := output.JSON(&after, report); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data.Bytes(), after.Bytes()) || report.Findings[0].Category != "javascript_framework" || report.Findings[0].State != "inferred" || report.Findings[0].Evidence[0].RuleID != "server-host-attributes" {
		t.Fatal("presentation changed category, state or evidence")
	}
}
