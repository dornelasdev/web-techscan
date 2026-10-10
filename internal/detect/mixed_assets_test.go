package detect_test

import (
	"net/http"
	"reflect"
	"testing"

	"webscan/internal/detect"
)

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
