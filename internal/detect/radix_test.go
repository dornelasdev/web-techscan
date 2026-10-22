package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

// Authored flat object properties model shipped string mappings, not execution.
func radixMappings(family string) []string {
	return []string{
		fmt.Sprintf(`"--radix-%s-content-transform-origin":"var(--radix-popper-transform-origin)"`, family),
		fmt.Sprintf(`"--radix-%s-content-available-width":"var(--radix-popper-available-width)"`, family),
		fmt.Sprintf(`"--radix-%s-content-available-height":"var(--radix-popper-available-height)"`, family),
	}
}

func radixObject(parts []string) string { return "{" + strings.Join(parts, ",") + "}" }

func requireRadix(t *testing.T, got []detect.Finding, rules, urls []string) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "radix-ui" || got[0].Name != "Radix UI" || got[0].Category != detect.UIFramework || got[0].State != detect.Inferred || len(got[0].Evidence) != len(rules) {
		t.Fatalf("findings=%+v", got)
	}
	for i, e := range got[0].Evidence {
		if e.RuleID != rules[i] || e.AssetURL != urls[i] || e.InferredFrom != "" || e.Description == "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.AssetJavaScript}}) {
			t.Fatalf("evidence=%+v", e)
		}
		for _, raw := range []string{"--radix-", "private-token", "1.1.15", "1.2.8"} {
			if strings.Contains(e.Description, raw) {
				t.Errorf("raw data in description: %q", e.Description)
			}
		}
	}
}

func TestRadixStyleMappings(t *testing.T) {
	engine := bundledEngine(t)
	for _, family := range []string{"popover", "tooltip"} {
		valid := radixObject(radixMappings(family))
		fixture := "radix-popover.js"
		if family == "tooltip" {
			fixture = "radix-tooltip.min.js"
		}
		for name, body := range map[string]string{
			"compact":             "const styles=" + valid + ";",
			"single-quotes":       strings.ReplaceAll(valid, `"`, `'`),
			"spacing":             "const styles = {\n" + strings.Join(radixMappings(family), ",\n") + "\n};",
			"fixture":             string(htmlFixture(t, fixture)),
			"other-flat-fields":   strings.Replace(valid, "{", "{...props.style,color:'red',", 1),
			"trailing-comma":      strings.TrimSuffix(valid, "}") + ",}",
			"trailing-properties": strings.TrimSuffix(valid, "}") + ",opacity:1}",
			"nested-object":       "const styles={style:" + valid + "};",
			// Raw matching does not validate JS syntax, comments or runtime use.
			"commented": "/* " + valid + " */",
			"repeated":  valid + valid,
		} {
			t.Run(family+"/"+name, func(t *testing.T) {
				url := "https://example.test/renamed?private-token=1"
				for _, status := range []int{0, 200, 403} {
					input := detect.Input{HTTPStatus: status, Assets: []detect.Asset{scriptAsset(url, body)}}
					got := engine.Detect(input)
					requireRadix(t, got, []string{"asset-" + family + "-style-mappings"}, []string{url})
					if !reflect.DeepEqual(got, engine.Detect(input)) {
						t.Fatal("unstable repeat scan")
					}
					got[0].Evidence[0].Signals[0].Source = detect.HTML
					requireRadix(t, engine.Detect(input), []string{"asset-" + family + "-style-mappings"}, []string{url})
				}
				if got := engine.Detect(detect.Input{}); len(got) != 0 {
					t.Fatalf("retained evidence: %+v", got)
				}
			})
		}
	}
}

func TestRadixStyleMappingNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	for _, family := range []string{"popover", "tooltip"} {
		parts := radixMappings(family)
		valid := radixObject(parts)
		otherFamily := "tooltip"
		if family == "tooltip" {
			otherFamily = "popover"
		}
		cases := map[string]string{
			"generic-states":         `const p={"data-state":"open","data-side":"bottom",role:"dialog"};`,
			"bare-prefix":            `const p={"--radix-color":"red"};`,
			"import-only":            `import {Popover,Tooltip} from "radix-ui";`,
			"component-name-only":    `const names=["PopoverContent","TooltipContent"];`,
			"css-declarations":       strings.ReplaceAll(strings.ReplaceAll(valid, `"`, ""), ",", ";"),
			"keys-only":              strings.Join([]string{"--radix-" + family + "-content-transform-origin", "--radix-" + family + "-content-available-width", "--radix-" + family + "-content-available-height"}, " "),
			"no-opening-brace":       strings.TrimPrefix(valid, "{"),
			"no-closing-brace":       strings.TrimSuffix(valid, "}"),
			"split-objects":          radixObject(parts[:1]) + ";" + radixObject(parts[1:]),
			"split-nested-object":    "{" + parts[0] + ",nested:" + radixObject(parts[1:]) + "}",
			"reordered":              radixObject([]string{parts[1], parts[0], parts[2]}),
			"intervening-property":   radixObject([]string{parts[0], "color:'red'", parts[1], parts[2]}),
			"intervening-comment":    strings.Replace(valid, ",", ",/*gap*/", 1),
			"computed-key":           strings.Replace(valid, parts[0], "["+strings.SplitN(parts[0], ":", 2)[0]+"]:"+strings.SplitN(parts[0], ":", 2)[1], 1),
			"template-string":        strings.ReplaceAll(valid, `"`, "`"),
			"css-space-in-value":     strings.Replace(valid, "var(--radix-popper-transform-origin)", "var( --radix-popper-transform-origin )", 1),
			"concatenated-value":     strings.Replace(valid, `"var(--radix-popper-transform-origin)"`, `"var("+"--radix-popper-transform-origin)"`, 1),
			"escaped-key":            strings.Replace(valid, "--radix-", `--\u0072adix-`, 1),
			"wrong-case":             strings.ReplaceAll(valid, "radix", "Radix"),
			"incorrect-family":       strings.ReplaceAll(valid, "--radix-"+family, "--custom-"+family),
			"mixed-family":           strings.Replace(valid, "--radix-"+family+"-content-available-height", "--radix-select-content-available-height", 1),
			"mixed-supported-family": strings.Replace(valid, "--radix-"+family+"-content-available-height", "--radix-"+otherFamily+"-content-available-height", 1),
			"wrong-height-target":    strings.Replace(valid, "var(--radix-popper-available-height)", "var(--radix-popper-anchor-height)", 1),
			"unclosed-value":         strings.Replace(valid, `origin)"`, `origin)`, 1),
			"mismatched-key-quotes":  strings.Replace(valid, `origin":`, `origin':`, 1),
		}
		for mask := 0; mask < 7; mask++ {
			var partial []string
			for i, part := range parts {
				if mask&(1<<i) != 0 {
					partial = append(partial, part)
				}
			}
			cases[fmt.Sprintf("partial-%d", mask)] = radixObject(partial)
		}
		for i, part := range parts {
			keyval := strings.SplitN(part, ":", 2)
			cases[fmt.Sprintf("key-suffix-%d", i)] = strings.Replace(valid, keyval[0], strings.TrimSuffix(keyval[0], `"`)+`-other"`, 1)
			cases[fmt.Sprintf("value-suffix-%d", i)] = strings.Replace(valid, keyval[1], strings.TrimSuffix(keyval[1], `"`)+`other"`, 1)
			cases[fmt.Sprintf("wrong-value-%d", i)] = strings.Replace(valid, keyval[1], `"var(--custom)"`, 1)
		}
		for name, body := range cases {
			t.Run(family+"/"+name, func(t *testing.T) {
				if got := engine.Detect(detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/radix-ui.js", body)}}); len(got) != 0 {
					t.Fatalf("findings=%+v", got)
				}
			})
		}
	}
}

func TestRadixStyleMappingIsolation(t *testing.T) {
	engine := bundledEngine(t)
	for _, family := range []string{"popover", "tooltip"} {
		parts := radixMappings(family)
		valid := radixObject(parts)
		cases := map[string]detect.Input{
			"inline":          {HTML: []byte("<script>" + valid + "</script>")},
			"headers-cookies": {Headers: http.Header{"X-Marker": {valid}}, CookieNames: []string{valid}},
			"css":             {Assets: []detect.Asset{cssAsset("https://example.test/file", valid)}},
			"empty-url":       {Assets: []detect.Asset{scriptAsset("", valid)}},
			"filename":        {Assets: []detect.Asset{scriptAsset("https://example.test/@radix-ui/react-"+family+".min.js", "generic")}},
		}
		for mask := 1; mask < 7; mask++ {
			var left, right []string
			for i, part := range parts {
				if mask&(1<<i) != 0 {
					left = append(left, part)
				} else {
					right = append(right, part)
				}
			}
			l, r := radixObject(left), radixObject(right)
			cases[fmt.Sprintf("split-files-%d", mask)] = detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/one", l), scriptAsset("https://example.test/two", r)}}
			cases[fmt.Sprintf("split-same-url-%d", mask)] = detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/one", l), scriptAsset("https://example.test/one", r)}}
			cases[fmt.Sprintf("split-kind-%d", mask)] = detect.Input{Assets: []detect.Asset{scriptAsset("https://example.test/one", l), cssAsset("https://example.test/two", r)}}
			cases[fmt.Sprintf("split-page-%d", mask)] = detect.Input{HTML: []byte(l), Assets: []detect.Asset{scriptAsset("https://example.test/file", r)}}
		}
		for name, input := range cases {
			t.Run(family+"/"+name, func(t *testing.T) {
				if got := engine.Detect(input); len(got) != 0 {
					t.Fatalf("findings=%+v", got)
				}
			})
		}
	}
}

func TestRadixEvidenceAndIndependentTechnologies(t *testing.T) {
	engine := bundledEngine(t)
	popover, tooltip := radixObject(radixMappings("popover")), radixObject(radixMappings("tooltip"))
	one, two := "https://example.test/one", "https://example.test/two"
	input := detect.Input{Assets: []detect.Asset{scriptAsset(two, tooltip+tooltip), scriptAsset(one, popover+tooltip), scriptAsset(two, tooltip)}}
	got := engine.Detect(input)
	requireRadix(t, got, []string{"asset-popover-style-mappings", "asset-tooltip-style-mappings", "asset-tooltip-style-mappings"}, []string{one, two, one})
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Fatal("unstable evidence")
	}
	input.Headers = http.Header{"Server": {"nginx"}, "X-Powered-By": {"Next.js"}}
	input.Assets[1].Body = []byte(popover + tooltip + reactClientAssignment + reactElementSymbol)
	input.Assets = append(input.Assets, cssAsset("https://example.test/styles", tailwind3Banner+tailwind3Preflight))
	got = engine.Detect(input)
	var ids []string
	for _, f := range got {
		ids = append(ids, f.ID)
	}
	if !reflect.DeepEqual(ids, []string{"nextjs", "nginx", "radix-ui", "react", "tailwindcss"}) {
		t.Fatalf("findings=%+v", got)
	}
	if got[2].State != detect.Inferred || got[3].State != detect.Inferred || got[4].State != detect.Inferred {
		t.Fatalf("unexpected upgrade: %+v", got)
	}
	got[2].Evidence[0].AssetURL = "changed"
	if engine.Detect(input)[2].Evidence[0].AssetURL != one {
		t.Fatal("retained mutated evidence")
	}
}
