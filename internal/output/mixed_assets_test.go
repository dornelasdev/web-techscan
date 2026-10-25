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
	domURL := "https://example.test/renderer%3Fname?private-dom=1"
	angularURL := "https://example.test/component?private-angular=1"
	tailwindURL := "https://example.test/tailwind%3Fname?private-tailwind=1"
	findings := []detect.Finding{
		{ID: "bootstrap", Name: "Bootstrap", Category: detect.UIFramework, State: detect.Inferred,
			Evidence: []detect.Evidence{{RuleID: "asset-css-banner-and-buttons", Description: "CSS evidence", AssetURL: cssURL, Signals: []detect.Signal{{Source: detect.AssetCSS}}}}},
		{ID: "nextjs", Name: "Next.js", Category: detect.Framework, State: detect.Detected,
			Evidence: []detect.Evidence{
				{RuleID: "asset-build-manifest", Description: "JS evidence", AssetURL: jsURL, Signals: []detect.Signal{{Source: detect.AssetJavaScript}}},
				{RuleID: "powered-by-header", Description: "Page evidence", Signals: []detect.Signal{{Source: detect.Header, Name: "X-Powered-By"}}},
			}},
		{ID: "nuxt", Name: "Nuxt", Category: detect.Framework, State: detect.Detected,
			Evidence: []detect.Evidence{
				{RuleID: "payload-html-markers", Description: "Nuxt HTML evidence", Signals: []detect.Signal{{Source: detect.HTML}, {Source: detect.HTML}}},
				{RuleID: "powered-by-header", Description: "Nuxt header evidence", Signals: []detect.Signal{{Source: detect.Header, Name: "X-Powered-By"}}},
			}},
		{ID: "react", Name: "React", Category: detect.JSFramework, State: detect.Inferred,
			Evidence: []detect.Evidence{
				{RuleID: "asset-client-runtime", Description: "React runtime evidence", AssetURL: jsURL, Signals: []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}},
				{RuleID: "asset-dom-runtime", Description: "ReactDOM evidence", AssetURL: jsURL, Signals: []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}},
				{RuleID: "asset-dom-runtime", Description: "Separate ReactDOM evidence", AssetURL: domURL, Signals: []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}},
			}},
		{ID: "vue", Name: "Vue", Category: detect.JSFramework, State: detect.Inferred,
			Evidence: []detect.Evidence{{RuleID: "asset-renderer-runtime", Description: "Vue runtime evidence", AssetURL: jsURL, Signals: []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}}}},
		{ID: "angular", Name: "Angular", Category: detect.JSFramework, State: detect.Inferred,
			Evidence: []detect.Evidence{
				{RuleID: "asset-component-runtime", Description: "Angular runtime evidence", AssetURL: angularURL, Signals: []detect.Signal{{Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}, {Source: detect.AssetJavaScript}}},
				{RuleID: "server-host-attributes", Description: "Angular host evidence", Signals: []detect.Signal{{Source: detect.HTML}}},
			}},
		{ID: "tailwindcss", Name: "Tailwind CSS", Category: detect.UIFramework, State: detect.Inferred,
			Evidence: []detect.Evidence{
				{RuleID: "asset-css-v3-banner-and-preflight", Description: "Shared CSS evidence", AssetURL: cssURL, Signals: []detect.Signal{{Source: detect.AssetCSS}, {Source: detect.AssetCSS}}},
				{RuleID: "asset-css-v4-banner-and-translate", Description: "Second CSS rule", AssetURL: cssURL, Signals: []detect.Signal{{Source: detect.AssetCSS}, {Source: detect.AssetCSS}, {Source: detect.AssetCSS}}},
				{RuleID: "asset-css-v4-banner-and-translate", Description: "Separate CSS capture", AssetURL: tailwindURL, Signals: []detect.Signal{{Source: detect.AssetCSS}, {Source: detect.AssetCSS}, {Source: detect.AssetCSS}}},
			}},
		{ID: "radix-ui", Name: "Radix UI", Category: detect.UIFramework, State: detect.Inferred,
			Evidence: []detect.Evidence{
				{RuleID: "asset-popover-style-mappings", Description: "Popover evidence", AssetURL: jsURL, Signals: []detect.Signal{{Source: detect.AssetJavaScript}}},
				{RuleID: "asset-popover-style-mappings", Description: "Separate Popover capture", AssetURL: domURL, Signals: []detect.Signal{{Source: detect.AssetJavaScript}}},
				{RuleID: "asset-tooltip-style-mappings", Description: "Tooltip evidence", AssetURL: domURL, Signals: []detect.Signal{{Source: detect.AssetJavaScript}}},
			}},
		{ID: "shadcn-ui", Name: "shadcn/ui", Category: detect.UIFramework, State: detect.Inferred,
			Evidence: []detect.Evidence{{RuleID: "sidebar-html", Description: "Sidebar page evidence", Signals: []detect.Signal{{Source: detect.HTML}, {Source: detect.HTML}, {Source: detect.HTML}}}}},
	}
	// Synthetic catalog metadata, independent of the bundled catalog total.
	report := output.NewReport(fetch.Snapshot{OriginalURL: "https://example.test/", FinalURL: "https://example.test/"}, findings, len(findings))
	report.Assets = output.NewAssetReport(assets.Collection{Budget: outputBudget(t, "standard"), Status: "complete", Attempted: 5, Collected: 5, Items: []assets.Item{
		{Reference: assets.Reference{URL: cssURL, Kind: assets.Stylesheet}, Status: "collected"},
		{Reference: assets.Reference{URL: jsURL, Kind: assets.JavaScript}, Status: "collected"},
		{Reference: assets.Reference{URL: domURL, Kind: assets.JavaScript}, Status: "collected"},
		{Reference: assets.Reference{URL: angularURL, Kind: assets.JavaScript}, Status: "collected"},
		{Reference: assets.Reference{URL: tailwindURL, Kind: assets.Stylesheet}, Status: "collected"},
	}})
	before, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	redacted := report.RedactQueries()
	wantURLs := []string{"https://example.test/style%3Fname?[redacted]", "https://example.test/script?[redacted]", "https://example.test/renderer%3Fname?[redacted]", "https://example.test/component?[redacted]", "https://example.test/tailwind%3Fname?[redacted]"}
	for i, want := range wantURLs {
		if redacted.Assets.Items[i].URL != want {
			t.Fatalf("redacted report=%+v", redacted)
		}
	}
	// Every rule/URL record must retain its location and state, including
	// duplicate renderer rule IDs on different URLs and empty HTML URLs.
	for i, finding := range report.Findings {
		if redacted.Findings[i].ID != finding.ID || redacted.Findings[i].State != finding.State || len(redacted.Findings[i].Evidence) != len(finding.Evidence) {
			t.Fatalf("finding provenance changed: %+v", redacted.Findings[i])
		}
		for j, evidence := range finding.Evidence {
			want, _, hasQuery := strings.Cut(evidence.AssetURL, "?")
			if hasQuery {
				want += "?[redacted]"
			}
			got := redacted.Findings[i].Evidence[j]
			if got.AssetURL != want || got.RuleID != evidence.RuleID || got.Description != evidence.Description || got.InferredFrom != evidence.InferredFrom || !reflect.DeepEqual(got.Signals, evidence.Signals) {
				t.Fatalf("evidence provenance changed: got=%+v source=%+v", got, evidence)
			}
		}
	}
	if redacted.Findings[1].Evidence[1].AssetURL != "" || redacted.Findings[1].State != "detected" || redacted.Findings[0].State != "inferred" || !reflect.DeepEqual(redacted.RedactQueries(), redacted) {
		t.Fatal("redaction changed page evidence/states or was not idempotent")
	}
	for _, index := range []int{3, 4} {
		if redacted.Findings[index].State != "inferred" || redacted.Findings[index].Evidence[0].AssetURL != wantURLs[1] || !reflect.DeepEqual(redacted.Findings[index].Evidence[0].Signals, report.Findings[index].Evidence[0].Signals) {
			t.Fatalf("runtime provenance changed: %+v", redacted.Findings[index])
		}
	}
	if !reflect.DeepEqual(redacted.Findings[2], report.Findings[2]) || !reflect.DeepEqual(redacted.Findings[8], report.Findings[8]) || redacted.Findings[8].Evidence[0].AssetURL != "" {
		t.Fatal("redaction changed Nuxt or shadcn page evidence")
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
	}
	for i := range redacted.Assets.Items {
		redacted.Assets.Items[i].URL = "changed"
	}
	after, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || findings[0].Evidence[0].AssetURL != cssURL || findings[1].Evidence[0].AssetURL != jsURL || findings[3].Evidence[0].AssetURL != jsURL || findings[3].Evidence[2].AssetURL != domURL || findings[4].Evidence[0].AssetURL != jsURL || findings[5].Evidence[0].AssetURL != angularURL || findings[6].Evidence[2].AssetURL != tailwindURL || findings[7].Evidence[1].AssetURL != domURL || findings[8].Evidence[0].AssetURL != "" {
		t.Fatal("redaction shares source provenance")
	}
}
