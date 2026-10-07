package detect_test

import (
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const railsParam = `<meta name="csrf-param" content="authenticity_token">`
const railsToken = `<meta name="csrf-token" content="private-rails-token">`

func requireRails(t *testing.T, got []detect.Finding, want bool) {
	t.Helper()
	if !want {
		if len(got) != 0 {
			t.Fatalf("unexpected findings: %+v", got)
		}
		return
	}
	if len(got) != 1 || got[0].ID != "rails" || got[0].Name != "Ruby on Rails" || got[0].Category != detect.Framework || got[0].State != detect.Inferred {
		t.Fatalf("want only inferred Rails without language guesses, got %+v", got)
	}
	if len(got[0].Evidence) != 1 {
		t.Fatalf("unexpected evidence: %+v", got[0].Evidence)
	}
	e := got[0].Evidence[0]
	if e.RuleID != "csrf-meta-pair" || e.Description == "" || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.HTML}, {Source: detect.HTML}}) {
		t.Errorf("unexpected paired evidence: %+v", e)
	}
}

func TestRailsPairedMetadata(t *testing.T) {
	engine := bundledEngine(t)
	requireRails(t, engine.Detect(detect.Input{HTML: htmlFixture(t, "rails-csrf.html")}), true)
	for _, body := range []string{railsParam + railsToken, railsToken + railsParam, strings.Repeat(railsParam+railsToken, 2), "<!--" + railsParam + railsToken + "-->"} {
		// Duplicate tags do not duplicate evidence. Comments remain a raw-HTML limitation.
		requireRails(t, engine.Detect(detect.Input{HTML: []byte(body)}), true)
	}
	for _, body := range []string{"", railsParam, railsToken, `<input type="hidden" name="authenticity_token">`, `<script src="/assets/turbo.js"></script>`} {
		requireRails(t, engine.Detect(detect.Input{HTML: []byte(body), CookieNames: []string{"_app_session", "_rails_session"}, Headers: http.Header{"X-Request-Id": {"123"}, "X-Runtime": {"0.123"}, "X-Powered-By": {"Rails"}}}), false)
	}
	// Strings in other signal sources cannot satisfy HTML requirements.
	requireRails(t, engine.Detect(detect.Input{Headers: http.Header{"X-Example": {railsParam + railsToken}}, CookieNames: []string{railsParam, railsToken}}), false)
}

func TestRailsMetaBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for _, marker := range []struct{ name, value, partner string }{
		{"csrf-param", "authenticity_token", railsToken},
		{"csrf-token", "private-rails-token", railsParam},
	} {
		for _, quote := range []string{`"`, `'`} {
			name := "name=" + quote + marker.name + quote
			content := "content=" + quote + marker.value + quote
			for _, pair := range []string{name + " " + content, content + " " + name} {
				for _, tag := range []string{
					"<meta " + pair + ">",
					"<META data-first='fixture'\n" + pair + " data-last=value />",
					"<meta " + strings.Replace(pair, " ", " data-middle=value ", 1) + ">",
				} {
					t.Run("positive/"+tag, func(t *testing.T) {
						requireRails(t, engine.Detect(detect.Input{HTML: []byte(tag + marker.partner)}), true)
					})
				}
			}
		}
		for i, tag := range []string{
			`<meta name="` + marker.name + `">`,
			`<meta content="` + marker.value + `">`,
			`<meta name="` + marker.name + `"><meta content="` + marker.value + `">`,
			`<meta data-name="` + marker.name + `" content="` + marker.value + `">`,
			`<meta name="` + marker.name + `" data-content="` + marker.value + `">`,
			`<meta-widget name="` + marker.name + `" content="` + marker.value + `">`,
			`<div name="` + marker.name + `" content="` + marker.value + `">`,
			`<meta name="` + strings.ToUpper(marker.name) + `" content="` + marker.value + `">`,
			`<meta name="` + marker.name + `-extra" content="` + marker.value + `">`,
			`<meta data-example='name="` + marker.name + `" content="` + marker.value + `"'>`,
			`<meta name="` + marker.name + `" data-example=' content="` + marker.value + `" '>`,
			`<meta content="` + marker.value + `" data-example=' name="` + marker.name + `" '>`,
			`<meta name="` + marker.name + `" content="` + marker.value + `"`,
			`<meta name="` + marker.name + `"content="` + marker.value + `">`,
			`<meta name=` + marker.name + ` content=` + marker.value + `>`,
			`&lt;meta name="` + marker.name + `" content="` + marker.value + `"&gt;`,
		} {
			t.Run(marker.name+"/negative/"+strconv.Itoa(i), func(t *testing.T) {
				requireRails(t, engine.Detect(detect.Input{HTML: []byte(tag + marker.partner)}), false)
			})
		}
	}
	requireRails(t, engine.Detect(detect.Input{HTML: []byte(`<META NAME = 'csrf-param' CONTENT = "authenticity_token"/><META CONTENT='token+/_=-' NAME='csrf-token'>`)}), true)
	for _, value := range []string{"", " ", "\t\n", "two tokens"} {
		requireRails(t, engine.Detect(detect.Input{HTML: []byte(railsParam + `<meta name="csrf-token" content="` + value + `">`)}), false)
	}
	for _, value := range []string{"AUTHENTICITY_TOKEN", "authenticity_token_extra", "custom_token", "authenticity&#95;token"} {
		requireRails(t, engine.Detect(detect.Input{HTML: []byte(railsToken + `<meta name="csrf-param" content="` + value + `">`)}), false)
	}
}

func TestRailsIndependentFrameworkEvidence(t *testing.T) {
	engine := bundledEngine(t)
	got := engine.Detect(detect.Input{HTML: []byte(railsParam + railsToken + djangoInput), CookieNames: []string{"csrftoken"}, Headers: http.Header{"Server": {"nginx"}}})
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
	}
	if !reflect.DeepEqual(ids, []string{"django", "nginx", "rails"}) {
		t.Fatalf("unexpected combined findings: %+v", got)
	}
	requireDjango(t, got[:1], true)
	requireRails(t, got[2:], true)
	// Django's token input cannot substitute for either Rails meta tag.
	for _, body := range []string{djangoInput + railsParam, djangoInput + railsToken} {
		requireDjango(t, engine.Detect(detect.Input{HTML: []byte(body), CookieNames: []string{"csrftoken"}}), true)
	}
}
