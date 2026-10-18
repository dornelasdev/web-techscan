package detect_test

import (
	"net/http"
	"strings"
	"testing"
	"testing/fstest"

	"webscan/internal/detect"
)

func TestCategoryMetadataAndValidation(t *testing.T) {
	for order, tc := range []struct {
		category              detect.Category
		group, label, heading string
	}{
		{detect.Framework, "Web development", "framework", "Web frameworks"},
		{detect.JSFramework, "Web development", "JavaScript framework", "JavaScript frameworks"},
		{detect.JSLibrary, "Web development", "JavaScript library", "JavaScript libraries"},
		{detect.UIFramework, "Web development", "UI framework", "UI frameworks"},
		{detect.CMS, "Web development", "CMS", "CMS"},
		{detect.Language, "Web development", "language", "Languages"},
		{detect.WebServer, "Infrastructure", "web server", "Web servers"},
		{detect.CDN, "Infrastructure", "CDN/edge", "CDN/edge"},
		{detect.LoadBalancer, "Infrastructure", "load balancer", "Load balancers"},
		{detect.WAF, "Infrastructure", "WAF", "WAFs"},
	} {
		t.Run(string(tc.category), func(t *testing.T) {
			want := detect.CategoryInfo{Group: tc.group, Label: tc.label, Heading: tc.heading, Order: order}
			info, ok := tc.category.Info()
			if !ok || info != want {
				t.Fatalf("metadata=%+v known=%t want=%+v", info, ok, want)
			}
			info.Group, info.Label, info.Heading, info.Order = "changed", "changed", "changed", -1
			if fresh, _ := tc.category.Info(); fresh != want {
				t.Fatal("returned metadata must not mutate category definitions")
			}
			data := strings.Replace(document(technology("example", validRule, "")), `"category":"framework"`, `"category":"`+string(tc.category)+`"`, 1)
			engine, err := detect.Load(fstest.MapFS{"rules.json": {Data: []byte(data)}})
			if err != nil {
				t.Fatal(err)
			}
			got := engine.Detect(detect.Input{Headers: http.Header{"Server": {"Example"}}})
			if len(got) != 1 || got[0].Category != tc.category || got[0].State != detect.Detected || len(got[0].Evidence) != 1 {
				t.Fatalf("category must propagate without changing matching: %+v", got)
			}
		})
	}
	for _, category := range []detect.Category{"", "unknown", "Framework", "javascript_libraries"} {
		info, ok := category.Info()
		if ok || info.Group != "Other" || info.Label != string(category) || info.Heading != string(category) || info.Order != 10 {
			t.Errorf("unexpected unknown-category fallback: %+v known=%t", info, ok)
		}
	}
}

func TestBundledTaxonomy(t *testing.T) {
	engine := bundledEngine(t)
	counts := make(map[detect.Category]int)
	for _, tech := range engine.Technologies() {
		want := detect.Framework
		switch tech.ID {
		case "angular", "react", "vue":
			want = detect.JSFramework
		case "jquery":
			want = detect.JSLibrary
		case "php", "python", "ruby":
			want = detect.Language
		case "apache", "iis", "jetty", "nginx":
			want = detect.WebServer
		case "django", "express", "laravel", "nextjs", "nuxt", "rails":
		default:
			want = tech.Category
		}
		if tech.Category != want {
			t.Errorf("%s category=%s want=%s", tech.ID, tech.Category, want)
		}
		if _, ok := tech.Category.Info(); !ok {
			t.Errorf("missing metadata for %s", tech.Category)
		}
		counts[tech.Category]++
	}
	if engine.Len() != 26 || len(counts) != 10 || counts[detect.Framework] != 6 || counts[detect.JSFramework] != 3 || counts[detect.JSLibrary] != 1 || counts[detect.Language] != 3 || counts[detect.WebServer] != 4 {
		t.Fatalf("unexpected catalog taxonomy: size=%d counts=%v", engine.Len(), counts)
	}
}
