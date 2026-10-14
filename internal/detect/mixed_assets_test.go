package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func TestFrontendFindingCombinations(t *testing.T) {
	engine := bundledEngine(t)
	css := bootstrapBanner + bootstrapButtons
	react := reactClientAssignment + reactElementSymbol + ";"
	vue := vueRuntimeFlag + vueAppAssignment + vueFragmentSymbol
	dom := strings.Join(reactDOMMarkers, "\n")
	angular := angularContextKey + angularComponentDefinition + angularHostVersionArray
	jsOne, jsTwo, cssURL := "https://example.test/z", "https://example.test/a", "https://example.test/style"
	type expectedEvidence struct {
		rule, url string
		source    detect.Source
		count     int
	}
	// All 256 signal-family subsets, including independent React client/DOM
	// and Angular HTML/JS evidence. Header upgrades and capture order stay
	// independent. This is synthetic coexistence, not real-site architecture.
	for mask := 0; mask < 256; mask++ {
		for headers := 0; headers < 4; headers++ {
			for _, reverse := range []bool{false, true} {
				t.Run(fmt.Sprintf("subset=%d/headers=%d/reverse=%t", mask, headers, reverse), func(t *testing.T) {
					bootstrap, next, nuxt, hasReact, hasVue := mask&1 != 0, mask&2 != 0, mask&4 != 0, mask&8 != 0, mask&16 != 0
					hasDOM, angularJS, angularHTML := mask&32 != 0, mask&64 != 0, mask&128 != 0
					nextHeader, nuxtHeader := headers&1 != 0, headers&2 != 0
					domText, angularText := dom, angular
					if reverse {
						domText = modernReactDOMText(domText)
						angularText = strings.ReplaceAll(angularText, "ɵcmp", `\u0275cmp`)
					}
					input := detect.Input{Headers: make(http.Header)}
					// Bootstrap text in JS must not supply a CSS finding, and
					// complete JS markers in CSS must not supply JS findings.
					jsBody := css + "\n"
					cssBody := "/* " + nextBuildAsset + react + vue + domText + angularText + angularHostTag + " */"
					if bootstrap {
						cssBody = css + cssBody
					}
					if next {
						jsBody += nextBuildAsset
						input.HTML = append(input.HTML, []byte(`<script id="__NEXT_DATA__"></script><script src="/_next/static/entry.js"></script>`)...)
					}
					if nuxt {
						input.HTML = append(input.HTML, []byte(nuxtDataScript+nuxtAssetScript)...)
					}
					if hasReact {
						jsBody += react
					}
					if hasVue {
						jsBody += vue
					}
					if hasDOM {
						jsBody += domText
					}
					if angularJS {
						jsBody += angularText
					}
					if angularHTML {
						input.HTML = append(input.HTML, []byte(angularHostTag)...)
					}
					// HTML text in accepted JS must not satisfy the host rule.
					jsBody += "/* " + angularHostTag + " */"
					if nextHeader {
						input.Headers.Add("X-Powered-By", "Next.js")
					}
					if nuxtHeader {
						input.Headers.Add("X-Powered-By", "Nuxt")
					}
					first, second := jsOne, jsTwo
					if reverse {
						first, second = second, first
					}
					input.Assets = []detect.Asset{scriptAsset(first, jsBody), cssAsset(cssURL, cssBody), scriptAsset(second, jsBody), scriptAsset(first, jsBody), cssAsset(cssURL, cssBody)}
					want := make(map[string][]expectedEvidence)
					states := make(map[string]detect.State)
					assetEvidence := func(id, rule string, count int) {
						want[id] = append(want[id], expectedEvidence{rule, first, detect.AssetJavaScript, count}, expectedEvidence{rule, second, detect.AssetJavaScript, count})
					}
					if bootstrap {
						want["bootstrap"] = []expectedEvidence{{"asset-css-banner-and-buttons", cssURL, detect.AssetCSS, 2}}
					}
					if next {
						assetEvidence("nextjs", "asset-build-manifest", 2)
						want["nextjs"] = append(want["nextjs"], expectedEvidence{"pages-html-markers", "", detect.HTML, 2})
					}
					if nextHeader {
						want["nextjs"] = append(want["nextjs"], expectedEvidence{"powered-by-header", "", detect.Header, 1})
						states["nextjs"] = detect.Detected
					}
					if nuxt {
						want["nuxt"] = []expectedEvidence{{"payload-html-markers", "", detect.HTML, 2}}
					}
					if nuxtHeader {
						want["nuxt"] = append(want["nuxt"], expectedEvidence{"powered-by-header", "", detect.Header, 1})
						states["nuxt"] = detect.Detected
					}
					if hasReact {
						assetEvidence("react", "asset-client-runtime", 2)
					}
					if hasDOM {
						assetEvidence("react", "asset-dom-runtime", 5)
					}
					if angularJS {
						assetEvidence("angular", "asset-component-runtime", 3)
					}
					if angularHTML {
						want["angular"] = append(want["angular"], expectedEvidence{"server-host-attributes", "", detect.HTML, 1})
					}
					if hasVue {
						assetEvidence("vue", "asset-renderer-runtime", 3)
					}
					got := engine.Detect(input)
					if len(got) != len(want) {
						t.Fatalf("findings=%+v want=%+v", got, want)
					}
					previous := ""
					for _, finding := range got {
						expected, ok := want[finding.ID]
						state := detect.Inferred
						if states[finding.ID] == detect.Detected {
							state = detect.Detected
						}
						category := detect.Framework
						if finding.ID == "bootstrap" {
							category = detect.UIFramework
						} else if finding.ID == "angular" || finding.ID == "react" || finding.ID == "vue" {
							category = detect.JSFramework
						}
						if !ok || finding.ID <= previous || finding.State != state || finding.Category != category || len(finding.Evidence) != len(expected) {
							t.Fatalf("finding=%+v want=%+v", finding, expected)
						}
						previous = finding.ID
						for i, e := range finding.Evidence {
							w := expected[i]
							if e.RuleID != w.rule || e.AssetURL != w.url || e.InferredFrom != "" || e.Description == "" || len(e.Signals) != w.count || strings.Contains(e.Description, "private-") {
								t.Fatalf("evidence=%+v want=%+v", e, w)
							}
							for _, signal := range e.Signals {
								name := ""
								if w.source == detect.Header {
									name = "X-Powered-By"
								}
								if signal.Source != w.source || signal.Name != name {
									t.Fatalf("signal=%+v want source=%s name=%s", signal, w.source, name)
								}
							}
						}
					}
					if !reflect.DeepEqual(got, engine.Detect(input)) || len(engine.Detect(detect.Input{})) != 0 {
						t.Error("unstable findings or retained scan state")
					}
				})
			}
		}
	}
}

func TestMixedAssetEvidenceIsolationAndPageUpgrade(t *testing.T) {
	engine := bundledEngine(t)
	jsURL, cssURL := "https://example.test/script", "https://example.test/style"
	css := bootstrapBanner + bootstrapButtons
	// Deliberately mix recognizable text into both bodies: their typed source,
	// not filename or marker familiarity, must determine which rule can match.
	js := scriptAsset(jsURL, nextBuildAsset+"\n"+css)
	style := cssAsset(cssURL, css+"\n"+nextBuildAsset)
	for _, header := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			input := detect.Input{Assets: []detect.Asset{js, style, js, style}}
			if reverse {
				input.Assets = []detect.Asset{style, js, style, js}
			}
			if header {
				input.Headers = http.Header{"X-Powered-By": {"Next.js"}}
			}
			got := engine.Detect(input)
			if len(got) != 2 || got[0].ID != "bootstrap" || got[1].ID != "nextjs" {
				t.Fatalf("header=%t reverse=%t findings=%+v", header, reverse, got)
			}
			wantNextState, wantNextEvidence := detect.Inferred, 1
			if header {
				wantNextState, wantNextEvidence = detect.Detected, 2
			}
			if got[0].State != detect.Inferred || len(got[0].Evidence) != 1 || got[1].State != wantNextState || len(got[1].Evidence) != wantNextEvidence {
				t.Fatalf("states/evidence=%+v", got)
			}
			for i, want := range []struct {
				url, rule string
				source    detect.Source
			}{{cssURL, "asset-css-banner-and-buttons", detect.AssetCSS}, {jsURL, "asset-build-manifest", detect.AssetJavaScript}} {
				e := got[i].Evidence[0]
				if e.AssetURL != want.url || e.RuleID != want.rule || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: want.source}, {Source: want.source}}) {
					t.Errorf("evidence=%+v want=%+v", e, want)
				}
			}
			if header {
				e := got[1].Evidence[1]
				if e.RuleID != "powered-by-header" || e.AssetURL != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.Header, Name: "X-Powered-By"}}) {
					t.Errorf("page evidence=%+v", e)
				}
			}
			if !reflect.DeepEqual(got, engine.Detect(input)) {
				t.Error("mixed evidence order is unstable")
			}
			got[0].Evidence[0].Signals[0].Source = "changed"
			got[1].Evidence[0].AssetURL = "changed"
			again := engine.Detect(input)
			if again[0].Evidence[0].Signals[0].Source != detect.AssetCSS || again[1].Evidence[0].AssetURL != jsURL || len(engine.Detect(detect.Input{})) != 0 {
				t.Error("mixed findings share state across scans")
			}
		}
	}
}
