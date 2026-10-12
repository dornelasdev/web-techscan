package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

const angularHostTag = `<app-shell ng-version="20.3.0" ng-server-context="ssg">`

func requireAngular(t *testing.T, got []detect.Finding, want bool) {
	t.Helper()
	if !want {
		if len(got) != 0 {
			t.Fatalf("unexpected findings=%+v", got)
		}
		return
	}
	if len(got) != 1 || got[0].ID != "angular" || got[0].Name != "Angular" || got[0].Category != detect.Framework || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
		t.Fatalf("want only inferred Angular, findings=%+v", got)
	}
	e := got[0].Evidence[0]
	// One compound HTML matcher binds both attributes to one tag.
	if e.RuleID != "server-host-attributes" || e.Description == "" || e.InferredFrom != "" || e.AssetURL != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.HTML}}) {
		t.Fatalf("evidence=%+v", e)
	}
	for _, value := range []string{"20.3.0", "private-context", "private-page-content"} {
		if strings.Contains(e.Description, value) {
			t.Errorf("raw value in evidence: %s", value)
		}
	}
}

func TestAngularServerHostAttributes(t *testing.T) {
	engine := bundledEngine(t)
	requireAngular(t, engine.Detect(detect.Input{HTML: htmlFixture(t, "angular-server.html")}), true)
	for _, body := range []string{angularHostTag, strings.Repeat(angularHostTag, 3), "<!-- " + angularHostTag + " -->"} {
		// Raw HTML matching can also see copied/commented marker pairs.
		requireAngular(t, engine.Detect(detect.Input{HTML: []byte(body)}), true)
	}
	for _, versionQuote := range []string{`"`, `'`} {
		for _, contextQuote := range []string{`"`, `'`} {
			version := "ng-version=" + versionQuote + "20.3.0" + versionQuote
			context := "ng-server-context=" + contextQuote + "private-context" + contextQuote
			for _, attrs := range []string{version + " " + context, context + " " + version, version + " data-middle='fixture' disabled " + context, context + " data-middle=fixture disabled " + version} {
				for _, tag := range []string{
					"<app-shell " + attrs + ">",
					"<DIV data-first='value'\n" + attrs + " data-last=value />",
					"<APP-ROOT " + strings.NewReplacer("ng-version=", "NG-VERSION \t=\n", "ng-server-context=", "NG-SERVER-CONTEXT \t=\n").Replace(attrs) + ">",
				} {
					t.Run("attributes/"+tag, func(t *testing.T) {
						requireAngular(t, engine.Detect(detect.Input{HTML: []byte(tag)}), true)
					})
				}
			}
		}
	}
}

func TestAngularHostAttributeValues(t *testing.T) {
	engine := bundledEngine(t)
	for _, version := range []string{"2.0.0", "9.1.0", "18.2.14", "20.3.0", "100.0.123"} {
		requireAngular(t, engine.Detect(detect.Input{HTML: []byte(strings.Replace(angularHostTag, "20.3.0", version, 1))}), true)
	}
	for _, context := range []string{"ssr", "ssg", "other", "SSR-123", "---"} {
		requireAngular(t, engine.Detect(detect.Input{HTML: []byte(strings.Replace(angularHostTag, "ssg", context, 1))}), true)
	}
	for _, version := range []string{"", "Angular", "0.0.0", "1.8.3", "020.3.0", "20.03.0", "20.3.00", "20", "20.3", "20.3.0.1", "v20.3.0", "20.3.0-compatible", "20.3.0-next.1", "20.3.0+custom", "0.0.0-PLACEHOLDER", " 20.3.0", "20.3.0 ", "20x3x0", "20&#46;3.0", "２０.3.0"} {
		t.Run("version/"+version, func(t *testing.T) {
			requireAngular(t, engine.Detect(detect.Input{HTML: []byte(strings.Replace(angularHostTag, "20.3.0", version, 1))}), false)
		})
	}
	for _, context := range []string{"", " ", "ssr ssg", "ssr_ssg", "ssr.ssg", "ssr/ssg", "ssr+ssg", "ssr&amp;ssg", "ssr\nssg", "sérver"} {
		t.Run("context/"+context, func(t *testing.T) {
			requireAngular(t, engine.Detect(detect.Input{HTML: []byte(strings.Replace(angularHostTag, "ssg", context, 1))}), false)
		})
	}
}

func TestAngularHostAttributeBoundaries(t *testing.T) {
	engine := bundledEngine(t)
	for i, body := range []string{
		"",
		`<app-root></app-root><script src="/angular.js"></script>`,
		`<body ng-app="app" ng-controller="MainCtrl">{{title}}</body>`,
		`<app-shell ng-version="20.3.0">`,
		`<app-shell ng-server-context="ssg">`,
		`<app-shell ng-version="20.3.0"><div ng-server-context="ssg">`,
		`<app-shell ng-server-context="ssg"><div ng-version="20.3.0">`,
		`<app-shell ng-version=20.3.0 ng-server-context="ssg">`,
		`<app-shell ng-version="20.3.0" ng-server-context=ssg>`,
		`<app-shell data-ng-version="20.3.0" ng-server-context="ssg">`,
		`<app-shell ng-version="20.3.0" data-ng-server-context="ssg">`,
		`<app-shell ng-version-extra="20.3.0" ng-server-context="ssg">`,
		`<app-shell ng-version="20.3.0" ng-server-context-extra="ssg">`,
		`<app-shell data-note='ng-version="20.3.0"' ng-server-context="ssg">`,
		`<app-shell ng-version="20.3.0" data-note='ng-server-context="ssg"'>`,
		`<app-shell data-note='ng-version="20.3.0" ng-server-context="ssg"'>`,
		`<app-shell ng-version="20.3.0"ng-server-context="ssg">`,
		`<app-shell ng-version="20.3.0" ng-server-context="ssg"`,
		`<app-shell ng-version="20.3.0" ng-server-context="ssg" /`,
		`</app-shell ng-version="20.3.0" ng-server-context="ssg">`,
		`<123 ng-version="20.3.0" ng-server-context="ssg">`,
		`<app-shell ng-version="20.3.0' ng-server-context="ssg">`,
		`&lt;app-shell ng-version="20.3.0" ng-server-context="ssg"&gt;`,
		`ng-version="20.3.0" ng-server-context="ssg"`,
	} {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			requireAngular(t, engine.Detect(detect.Input{HTML: []byte(body)}), false)
		})
	}
}

func TestAngularSignalIsolation(t *testing.T) {
	engine := bundledEngine(t)
	for name, input := range map[string]detect.Input{
		"headers-cookies":  {Headers: http.Header{"X-Powered-By": {"Angular"}, "X-Marker": {angularHostTag}}, CookieNames: []string{angularHostTag}},
		"javascript":       {Assets: []detect.Asset{scriptAsset("https://example.test/angular.js", angularHostTag)}},
		"css":              {Assets: []detect.Asset{cssAsset("https://example.test/angular.css", angularHostTag)}},
		"page-asset-split": {HTML: []byte(`<app-shell ng-version="20.3.0">`), Assets: []detect.Asset{scriptAsset("https://example.test/file", `<app-shell ng-server-context="ssg">`)}},
	} {
		t.Run(name, func(t *testing.T) { requireAngular(t, engine.Detect(input), false) })
	}
	input := detect.Input{HTML: []byte(angularHostTag), Headers: http.Header{"Server": {"nginx/1.26.2"}, "X-Powered-By": {"Next.js"}}}
	got := engine.Detect(input)
	if len(got) != 3 || got[0].ID != "angular" || got[0].State != detect.Inferred || got[1].ID != "nextjs" || got[1].State != detect.Detected || got[2].ID != "nginx" || got[2].State != detect.Detected {
		t.Fatalf("independent mixed findings=%+v", got)
	}
	if !reflect.DeepEqual(got, engine.Detect(input)) {
		t.Error("unstable evidence")
	}
	got[0].Evidence[0].Signals[0].Source = detect.Cookie
	if again := engine.Detect(input); again[0].Evidence[0].Signals[0].Source != detect.HTML {
		t.Error("shared evidence across calls")
	}
	requireAngular(t, engine.Detect(detect.Input{}), false)
}
