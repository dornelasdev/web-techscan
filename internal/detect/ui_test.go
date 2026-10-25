package detect_test

import (
	"fmt"
	"reflect"
	"testing"

	"webscan/internal/detect"
)

type uiEvidence struct {
	rule, url string
	source    detect.Source
	count     int
}

func requireUIFindings(t *testing.T, got []detect.Finding, want map[string][]uiEvidence) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("findings=%+v want=%v", got, want)
	}
	names := map[string]string{"bootstrap": "Bootstrap", "radix-ui": "Radix UI", "shadcn-ui": "shadcn/ui", "tailwindcss": "Tailwind CSS"}
	var ids []string
	for _, id := range []string{"bootstrap", "radix-ui", "shadcn-ui", "tailwindcss"} {
		if _, ok := want[id]; ok {
			ids = append(ids, id)
		}
	}
	for i, f := range got {
		if f.ID != ids[i] || f.Name != names[f.ID] || f.Category != detect.UIFramework || f.State != detect.Inferred || len(f.Evidence) != len(want[f.ID]) {
			t.Fatalf("finding=%+v want=%v", f, want)
		}
		for j, e := range f.Evidence {
			w := want[f.ID][j]
			signals := make([]detect.Signal, w.count)
			for k := range signals {
				signals[k].Source = w.source
			}
			if e.RuleID != w.rule || e.AssetURL != w.url || e.InferredFrom != "" || e.Description == "" || !reflect.DeepEqual(e.Signals, signals) {
				t.Fatalf("evidence=%+v want=%+v", e, w)
			}
		}
	}
}

func TestUIFrameworkCombinations(t *testing.T) {
	engine := bundledEngine(t)
	bootstrap := bootstrapBanner + bootstrapButtons
	shadcn := shadcnWrapper + shadcnInner + shadcnMenu
	popover, tooltip := radixObject(radixMappings("popover")), radixObject(radixMappings("tooltip"))
	tw3, tw4 := tailwind3Banner+tailwind3Preflight, tailwind4Banner+tailwind4Property+tailwind4Translate
	for mask := 0; mask < 16; mask++ {
		for _, separate := range []bool{false, true} {
			t.Run(fmt.Sprintf("mask=%d/separate=%t", mask, separate), func(t *testing.T) {
				jsURL, bURL, twURL := "https://example.test/runtime", "https://example.test/styles", "https://example.test/styles"
				radix, tw, rRule, tRule, tCount := popover, tw3, "asset-popover-style-mappings", "asset-css-v3-banner-and-preflight", 2
				if separate {
					twURL = "https://example.test/tailwind"
					radix, tw, rRule, tRule, tCount = tooltip, tw4, "asset-tooltip-style-mappings", "asset-css-v4-banner-and-translate", 3
				}
				// Complete wrong-source markers remain present when a technology is
				// absent from its own kind. Raw HTML in assets cannot supply shadcn.
				input := detect.Input{HTML: []byte("<style>" + bootstrap + tw3 + tw4 + "</style><script>" + popover + tooltip + "</script>")}
				jsBody := "/* " + bootstrap + tw3 + tw4 + shadcn + " */"
				cssBody := "/* " + popover + tooltip + shadcn + " */"
				bBody, twBody := cssBody, cssBody
				want := make(map[string][]uiEvidence)
				if mask&1 != 0 {
					bBody += bootstrap
					want["bootstrap"] = []uiEvidence{{"asset-css-banner-and-buttons", bURL, detect.AssetCSS, 2}}
				}
				if mask&2 != 0 {
					jsBody += radix
					want["radix-ui"] = []uiEvidence{{rRule, jsURL, detect.AssetJavaScript, 1}}
				}
				if mask&4 != 0 {
					input.HTML = append(input.HTML, []byte(shadcn)...)
					want["shadcn-ui"] = []uiEvidence{{"sidebar-html", "", detect.HTML, 3}}
				}
				if mask&8 != 0 {
					twBody += tw
					want["tailwindcss"] = []uiEvidence{{tRule, twURL, detect.AssetCSS, tCount}}
				}
				if separate {
					input.Assets = []detect.Asset{cssAsset(twURL, twBody), cssAsset(bURL, bBody), scriptAsset(jsURL, jsBody)}
				} else {
					input.Assets = []detect.Asset{scriptAsset(jsURL, jsBody), cssAsset(bURL, bBody+twBody)}
				}
				input.Assets = append(input.Assets, input.Assets...)
				got := engine.Detect(input)
				requireUIFindings(t, got, want)
				if !reflect.DeepEqual(got, engine.Detect(input)) {
					t.Fatal("unstable repeat scan")
				}
				if len(engine.Detect(detect.Input{})) != 0 {
					t.Fatal("retained findings")
				}
			})
		}
	}
}

func TestUIFrameworkRuleURLOrdering(t *testing.T) {
	engine := bundledEngine(t)
	css := bootstrapBanner + bootstrapButtons + tailwind3Banner + tailwind3Preflight + tailwind4Banner + tailwind4Property + tailwind4Translate
	js := radixObject(radixMappings("popover")) + radixObject(radixMappings("tooltip"))
	jsB, jsA, cssB, cssA := "https://example.test/js-b", "https://example.test/js-a", "https://example.test/css-b", "https://example.test/css-a"
	input := detect.Input{HTML: []byte(shadcnWrapper + shadcnInner + shadcnMenu), Assets: []detect.Asset{scriptAsset(jsB, js+js), cssAsset(cssB, css+css), scriptAsset(jsA, js), cssAsset(cssA, css), scriptAsset(jsB, js), cssAsset(cssB, css)}}
	want := map[string][]uiEvidence{
		"bootstrap":   {{"asset-css-banner-and-buttons", cssB, detect.AssetCSS, 2}, {"asset-css-banner-and-buttons", cssA, detect.AssetCSS, 2}},
		"radix-ui":    {{"asset-popover-style-mappings", jsB, detect.AssetJavaScript, 1}, {"asset-popover-style-mappings", jsA, detect.AssetJavaScript, 1}, {"asset-tooltip-style-mappings", jsB, detect.AssetJavaScript, 1}, {"asset-tooltip-style-mappings", jsA, detect.AssetJavaScript, 1}},
		"shadcn-ui":   {{"sidebar-html", "", detect.HTML, 3}},
		"tailwindcss": {{"asset-css-v3-banner-and-preflight", cssB, detect.AssetCSS, 2}, {"asset-css-v3-banner-and-preflight", cssA, detect.AssetCSS, 2}, {"asset-css-v4-banner-and-translate", cssB, detect.AssetCSS, 3}, {"asset-css-v4-banner-and-translate", cssA, detect.AssetCSS, 3}},
	}
	got := engine.Detect(input)
	requireUIFindings(t, got, want)
	got[0].Evidence[0].AssetURL = "changed"
	got[2].Evidence[0].Signals[0].Source = detect.Header
	requireUIFindings(t, engine.Detect(input), want)
}

func TestUIFrameworkPartialMarkersPreserveOtherFindings(t *testing.T) {
	engine := bundledEngine(t)
	b, tw := bootstrapBanner+bootstrapButtons, tailwind4Banner+tailwind4Property+tailwind4Translate
	r := radixObject(radixMappings("popover"))
	s := shadcnWrapper + shadcnInner + shadcnMenu
	for _, missing := range []string{"bootstrap", "radix-ui", "shadcn-ui", "tailwindcss"} {
		t.Run(missing, func(t *testing.T) {
			input := detect.Input{HTML: []byte(s)}
			css, js := b+tw, r
			want := map[string][]uiEvidence{"bootstrap": {{"asset-css-banner-and-buttons", "https://example.test/styles", detect.AssetCSS, 2}}, "radix-ui": {{"asset-popover-style-mappings", "https://example.test/runtime", detect.AssetJavaScript, 1}}, "shadcn-ui": {{"sidebar-html", "", detect.HTML, 3}}, "tailwindcss": {{"asset-css-v4-banner-and-translate", "https://example.test/styles", detect.AssetCSS, 3}}}
			switch missing {
			case "bootstrap":
				css = bootstrapBanner + tw
				input.Assets = append(input.Assets, cssAsset("https://example.test/part", bootstrapButtons))
			case "tailwindcss":
				css = b + tailwind4Banner + tailwind4Property
				input.Assets = append(input.Assets, cssAsset("https://example.test/part", tailwind4Translate))
			case "radix-ui":
				parts := radixMappings("popover")
				js = radixObject(parts[:1]) + radixObject(parts[1:])
			case "shadcn-ui":
				input.HTML = []byte(shadcnInner + shadcnMenu)
			}
			delete(want, missing)
			// Complete markers in the other source kind must not rescue the
			// deliberately incomplete rule, even with three other UI findings.
			input.Assets = append(input.Assets, scriptAsset("https://example.test/runtime", js+"/* "+b+tw+s+" */"), cssAsset("https://example.test/styles", css+"/* "+r+s+" */"))
			requireUIFindings(t, engine.Detect(input), want)
		})
	}
}
