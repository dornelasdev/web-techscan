package detect_test

import (
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const djangoInput = `<input type="hidden" name="csrfmiddlewaretoken" value="private-token">`

func requireDjango(t *testing.T, got []detect.Finding, want bool) {
	t.Helper()
	if !want {
		if len(got) != 0 {
			t.Fatalf("unexpected findings: %+v", got)
		}
		return
	}
	if len(got) != 1 || got[0].ID != "django" || got[0].Name != "Django" || got[0].Category != detect.Framework || got[0].State != detect.Inferred {
		t.Fatalf("want only inferred Django, no language guesses; got %+v", got)
	}
	if len(got[0].Evidence) != 1 {
		t.Fatalf("unexpected evidence: %+v", got[0].Evidence)
	}
	e := got[0].Evidence[0]
	if e.RuleID != "csrf-cookie-and-input" || e.InferredFrom != "" || e.Description == "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.Cookie}, {Source: detect.HTML}}) {
		t.Errorf("unexpected paired evidence: %+v", e)
	}
}

func TestDjangoRequiresCookieAndHTML(t *testing.T) {
	engine := bundledEngine(t)
	fixture := htmlFixture(t, "django-csrf.html")
	for _, names := range [][]string{{"csrftoken"}, {"sessionid", "csrftoken"}, {"csrftoken", "csrftoken", "unrelated"}} {
		requireDjango(t, engine.Detect(detect.Input{CookieNames: names, HTML: fixture}), true)
		// Preserve the existing policy: even the default cookie pair alone is insufficient.
		requireDjango(t, engine.Detect(detect.Input{CookieNames: names}), false)
	}
	for _, names := range [][]string{nil, {"sessionid"}, {"custom_csrf"}, {"CSRFTOKEN"}, {"csrftoken_extra"}, {"mycsrftoken"}, {"csrftoken\n"}, {"XSRF-TOKEN"}} {
		requireDjango(t, engine.Detect(detect.Input{CookieNames: names, HTML: fixture}), false)
	}
	for _, headers := range []http.Header{
		{"Set-Cookie": {"csrftoken=private-token"}}, {"Cookie": {"csrftoken=private-token"}},
		{"X-Powered-By": {"Django"}}, {"Server": {"WSGIServer/0.2 CPython/3.12"}},
	} {
		requireDjango(t, engine.Detect(detect.Input{Headers: headers, HTML: fixture}), false)
	}
	for _, body := range []string{djangoInput + djangoInput, "<!--" + djangoInput + "-->"} {
		// Copied/commented tags remain a documented limitation of raw HTML matching.
		requireDjango(t, engine.Detect(detect.Input{CookieNames: []string{"csrftoken"}, HTML: []byte(body)}), true)
	}
}

func TestDjangoInputBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for _, quote := range []string{`"`, `'`} {
		name := "name=" + quote + "csrfmiddlewaretoken" + quote
		typeAttr := "type=" + quote + "hidden" + quote
		for _, pair := range []string{name + " " + typeAttr, typeAttr + " " + name} {
			for _, body := range []string{
				"<input " + pair + ">",
				"<INPUT data-first='fixture'\n" + pair + " value='private-token' disabled />",
				"<input " + strings.Replace(pair, " ", " data-middle=fixture ", 1) + ">",
			} {
				t.Run("positive/"+body, func(t *testing.T) {
					requireDjango(t, engine.Detect(detect.Input{CookieNames: []string{"csrftoken"}, HTML: []byte(body)}), true)
				})
			}
		}
	}
	requireDjango(t, engine.Detect(detect.Input{CookieNames: []string{"csrftoken"}, HTML: []byte(`<INPUT NAME = 'csrfmiddlewaretoken' TYPE = "HIDDEN">`)}), true)
	for i, body := range []string{
		"", "csrfmiddlewaretoken", `<input name="csrfmiddlewaretoken">`, `<input type="hidden">`,
		`<input type="text" name="csrfmiddlewaretoken">`, `<input type="hiddenish" name="csrfmiddlewaretoken">`,
		`<input type="hidden" name="CSRFmiddlewaretoken">`, `<input type="hidden" name="csrfmiddlewaretoken-extra">`,
		`<input type="hidden" data-name="csrfmiddlewaretoken">`, `<input data-type="hidden" name="csrfmiddlewaretoken">`,
		`<input type="hidden"><input name="csrfmiddlewaretoken">`,
		`<div type="hidden" name="csrfmiddlewaretoken">`, `<input-widget type="hidden" name="csrfmiddlewaretoken">`,
		`<input:type type="hidden" name="csrfmiddlewaretoken">`,
		`<input data-example='type="hidden" name="csrfmiddlewaretoken"'>`,
		`<input type="hidden" data-example=' name="csrfmiddlewaretoken" '>`,
		`<input name="csrfmiddlewaretoken" data-example=' type="hidden" '>`,
		`<input type="hidden" name="csrfmiddlewaretoken"`,
		`<input type="hidden" name="csrfmiddlewaretoken" value="unfinished`,
		`<input type="hidden"name="csrfmiddlewaretoken">`,
		`<input/type="hidden" name="csrfmiddlewaretoken">`,
		`<input type=hidden name=csrfmiddlewaretoken>`,
		`&lt;input type="hidden" name="csrfmiddlewaretoken"&gt;`,
		`<input type="hidden" name="csrfmiddleware&#116;oken">`,
		`<meta name="csrfmiddlewaretoken" content="hidden">`,
	} {
		t.Run("negative/"+strconv.Itoa(i), func(t *testing.T) {
			requireDjango(t, engine.Detect(detect.Input{CookieNames: []string{"csrftoken"}, HTML: []byte(body)}), false)
		})
	}
}

func TestDjangoMixedStack(t *testing.T) {
	engine := bundledEngine(t)
	got := engine.Detect(detect.Input{
		CookieNames: []string{"csrftoken", "laravel_session", "XSRF-TOKEN"},
		HTML:        []byte(djangoInput), Headers: http.Header{"Server": {"nginx"}},
	})
	var ids []string
	for _, finding := range got {
		ids = append(ids, finding.ID)
	}
	if !reflect.DeepEqual(ids, []string{"django", "laravel", "nginx", "php"}) {
		t.Fatalf("unexpected combined findings: %+v", got)
	}
	requireDjango(t, got[:1], true)
	if got[3].State != detect.Inferred || len(got[3].Evidence) != 1 || got[3].Evidence[0].InferredFrom != "laravel" {
		t.Errorf("language evidence crossed frameworks: %+v", got[3])
	}
}
