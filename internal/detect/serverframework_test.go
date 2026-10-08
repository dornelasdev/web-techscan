package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"sort"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func TestServerFrameworkSignalCombinations(t *testing.T) {
	engine := bundledEngine(t)
	// Exercise every subset of the six required signals. Signals from another
	// framework, or a valid server banner, must not complete a missing pair.
	const (
		nuxtID = 1 << iota
		nuxtAsset
		djangoCookie
		djangoField
		railsParameter
		railsCSRF
	)
	for _, server := range []struct{ id, valid, invalid string }{
		{"apache", "Apache/2.4.62 (Unix) PHP/8.3.12", "Apache/2..4"},
		{"iis", "Microsoft-IIS/10.0", "Microsoft-IIS/10..0"},
		{"nginx", "nginx/1.26.2 (Ubuntu)", "nginx/1..2"},
	} {
		for _, valid := range []bool{true, false} {
			for mask := 0; mask < 1<<6; mask++ {
				t.Run(fmt.Sprintf("%s/valid=%t/signals=%06b", server.id, valid, mask), func(t *testing.T) {
					banner := server.invalid
					if valid {
						banner = server.valid
					}
					input := detect.Input{
						Headers:     http.Header{"Server": {banner}},
						CookieNames: []string{"sessionid", "_app_session", "XSRF-TOKEN"},
					}
					for _, marker := range []struct {
						bit  int
						html string
					}{
						{nuxtID, nuxtDataScript}, {nuxtAsset, nuxtAssetScript},
						{djangoField, djangoInput}, {railsParameter, railsParam}, {railsCSRF, railsToken},
					} {
						if mask&marker.bit != 0 {
							input.HTML = append(input.HTML, marker.html...)
						}
					}
					if mask&djangoCookie != 0 {
						input.CookieNames = append(input.CookieNames, "csrftoken")
					}
					wantIDs := []string{}
					if valid {
						wantIDs = append(wantIDs, server.id)
					}
					for _, pair := range []struct {
						id   string
						bits int
					}{
						{"nuxt", nuxtID | nuxtAsset}, {"django", djangoCookie | djangoField}, {"rails", railsParameter | railsCSRF},
					} {
						if mask&pair.bits == pair.bits {
							wantIDs = append(wantIDs, pair.id)
						}
					}
					sort.Strings(wantIDs)
					got := engine.Detect(input)
					gotIDs := []string{}
					for _, finding := range got {
						gotIDs = append(gotIDs, finding.ID)
					}
					if !reflect.DeepEqual(gotIDs, wantIDs) {
						t.Fatalf("findings=%+v want IDs=%v, without language guesses", got, wantIDs)
					}
					for i, finding := range got {
						switch finding.ID {
						case "nuxt":
							requireNuxt(t, got[i:i+1], true, false)
						case "django":
							requireDjango(t, got[i:i+1], true)
						case "rails":
							requireRails(t, got[i:i+1], true)
						default:
							if finding.Category != detect.WebServer || finding.State != detect.Detected || len(finding.Evidence) != 1 {
								t.Fatalf("unexpected server finding: %+v", finding)
							}
							e := finding.Evidence[0]
							if e.RuleID != "server-header" || e.InferredFrom != "" || !strings.Contains(e.Description, "may be an intermediary") || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.Header, Name: "Server"}}) {
								t.Errorf("unexpected server evidence: %+v", e)
							}
						}
					}
					if empty := engine.Detect(detect.Input{}); len(empty) != 0 {
						t.Errorf("findings leaked into a subsequent empty scan: %+v", empty)
					}
				})
			}
		}
	}
}
