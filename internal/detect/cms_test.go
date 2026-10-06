package detect_test

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"webscan/internal/detect"
)

func TestCMSGeneratorMeta(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct {
		id, product string
		variants    []string
	}{
		{"wordpress", "WordPress 6.8.3", []string{"WordPress", "WordPress 6.9-beta1"}},
		{"drupal", "Drupal 11 (https://www.drupal.org)", []string{"Drupal 10", "Drupal 7 (http://drupal.org)"}},
		{"joomla", "Joomla! - Open Source Content Management", []string{"Joomla! - Open Source Content Management - Version 5.4.0", "Joomla! - Open Source Content Management - Version 5.4.0-rc1"}},
	} {
		t.Run(tc.id, func(t *testing.T) {
			bodies := []string{
				string(htmlFixture(t, tc.id+".html")),
				fmt.Sprintf(`<meta content='%s' name='generator'>`, tc.product),
				fmt.Sprintf("<META\nCONTENT = \"%s\" data-note='fixture'\nNAME = 'GENERATOR' />", tc.product),
				fmt.Sprintf(`<meta data-note="fixture" name="generator" lang=en content="%s" id="cms">`, tc.product),
			}
			for _, product := range tc.variants {
				bodies = append(bodies, fmt.Sprintf(`<meta name="generator" content="%s">`, product))
			}
			for _, body := range bodies {
				got := engine.Detect(detect.Input{HTML: []byte(body)})
				if len(got) != 1 || got[0].ID != tc.id || got[0].Category != detect.CMS || got[0].State != detect.Inferred {
					t.Fatalf("HTML=%q findings=%+v, want only inferred %s (no language inference)", body, got, tc.id)
				}
				if len(got[0].Evidence) != 1 || got[0].Evidence[0].RuleID != "generator-meta" || len(got[0].Evidence[0].Signals) != 1 || got[0].Evidence[0].Signals[0].Source != detect.HTML {
					t.Errorf("unexpected evidence: %+v", got[0].Evidence)
				}
			}
			for _, body := range []string{
				fmt.Sprintf(`<p>%s</p>`, tc.product),
				fmt.Sprintf(`<meta name="description" content="%s">`, tc.product),
				fmt.Sprintf(`<meta data-name="generator" content="%s">`, tc.product),
				fmt.Sprintf(`<meta name="generator" data-content="%s">`, tc.product),
				fmt.Sprintf(`<meta name="generatorish" content="%s">`, tc.product),
				fmt.Sprintf(`<metadata name="generator" content="%s">`, tc.product),
				fmt.Sprintf(`<meta-custom name="generator" content="%s">`, tc.product),
				fmt.Sprintf(`<meta name="generator"><meta content="%s">`, tc.product),
				fmt.Sprintf(`<meta content="%s"><meta name="generator">`, tc.product),
				fmt.Sprintf(`<meta name="generator" content="Not%s">`, tc.product),
				fmt.Sprintf(`<meta name="generator" content="%s-compatible">`, tc.product),
				fmt.Sprintf(`<meta name="generator' content="%s">`, tc.product),
				fmt.Sprintf(`<meta title='name="generator"' content="%s">`, tc.product),
				fmt.Sprintf(`<meta name="generator" title='content="%s"'>`, tc.product),
				fmt.Sprintf(`&lt;meta name="generator" content="%s"&gt;`, tc.product),
			} {
				if got := engine.Detect(detect.Input{HTML: []byte(body)}); len(got) != 0 {
					t.Errorf("near miss %q produced %+v", body, got)
				}
			}
		})
	}
}

func TestCMSVersionSuffixes(t *testing.T) {
	engine := bundledEngine(t)
	for _, tc := range []struct{ id, product string }{
		{"wordpress", "WordPress 6.8.3"},
		{"joomla", "Joomla! - Open Source Content Management - Version 5.4.0"},
	} {
		t.Run(tc.id, func(t *testing.T) {
			for _, suffix := range []string{"", "-alpha1", "-beta2", "-rc1", "-RC2"} {
				for _, template := range []string{
					`<meta name="generator" content="%s">`,
					`<meta content="%s" name="generator">`,
					`<meta name='generator' content='%s'>`,
					`<meta content='%s' name='generator'>`,
				} {
					body := fmt.Sprintf(template, tc.product+suffix)
					got := engine.Detect(detect.Input{HTML: []byte(body)})
					if len(got) != 1 || got[0].ID != tc.id || got[0].State != detect.Inferred {
						t.Errorf("valid version %q produced %+v", body, got)
					}
				}
			}
			for _, suffix := range []string{"-compatible", "-custom", "-", "-alpha", "-beta", "-rc", "-rc1-compatible", "-beta2extra", "-RC2.1"} {
				for _, template := range []string{
					`<meta name="generator" content="%s">`,
					`<meta content="%s" name="generator">`,
					`<meta name='generator' content='%s'>`,
					`<meta content='%s' name='generator'>`,
				} {
					body := fmt.Sprintf(template, tc.product+suffix)
					if got := engine.Detect(detect.Input{HTML: []byte(body)}); len(got) != 0 {
						t.Errorf("unsupported suffix %q produced %+v", body, got)
					}
				}
			}
		})
	}
}

func TestCMSRawHTMLLimitations(t *testing.T) {
	engine := bundledEngine(t)
	for _, id := range []string{"wordpress", "drupal", "joomla"} {
		body := htmlFixture(t, id+".html")
		// Raw matching does not distinguish copied/commented markup. Keep that
		// limitation explicit and inferred until a structural HTML source exists.
		for _, html := range []string{"<!--" + string(body) + "-->", strings.Repeat(string(body), 2)} {
			got := engine.Detect(detect.Input{HTML: []byte(html)})
			if len(got) != 1 || got[0].ID != id || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
				t.Errorf("expected one inferred %s, got %+v", id, got)
			}
		}
	}
}

func TestDrupalGeneratorHeader(t *testing.T) {
	engine := bundledEngine(t)
	for _, value := range []string{"Drupal 11 (https://www.drupal.org)", "Drupal 7 (http://drupal.org)", "Drupal 10.4.0", " drupal 11\t"} {
		got := engine.Detect(detect.Input{Headers: http.Header{"X-Generator": {value}}})
		if len(got) != 1 || got[0].ID != "drupal" || got[0].Category != detect.CMS || got[0].State != detect.Detected || got[0].Evidence[0].RuleID != "generator-header" {
			t.Errorf("header=%q produced %+v", value, got)
		}
	}
	for _, value := range []string{"Drupalish 11", "NotDrupal 11", "Drupal", "Drupal 11-compatible", "Drupal 11 (https://www.drupal.org.evil.test)", "Drupal 11, OtherCMS", "DrupalCache"} {
		if got := engine.Detect(detect.Input{Headers: http.Header{"X-Generator": {value}}}); len(got) != 0 {
			t.Errorf("near-miss header=%q produced %+v", value, got)
		}
	}
	got := engine.Detect(detect.Input{Headers: http.Header{"X-Generator": {"Drupal 11"}}, HTML: htmlFixture(t, "drupal.html")})
	if len(got) != 1 || got[0].State != detect.Detected || len(got[0].Evidence) != 2 {
		t.Fatalf("header should upgrade Drupal while retaining HTML evidence: %+v", got)
	}
}
