package detect_test

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"webscan/internal/detect"
)

// Authored opening-tag scaffolds; no DOM ancestry or component execution claim.
const shadcnWrapper = `<div data-slot="sidebar-wrapper" style="--sidebar-width:16rem;--sidebar-width-icon:3rem">`
const shadcnInner = `<div data-slot="sidebar-inner" data-sidebar="sidebar">`
const shadcnMenu = `<ul data-slot="sidebar-menu" data-sidebar="menu">`

func requireShadcn(t *testing.T, got []detect.Finding) {
	t.Helper()
	if len(got) != 1 || got[0].ID != "shadcn-ui" || got[0].Name != "shadcn/ui" || got[0].Category != detect.UIFramework || got[0].State != detect.Inferred || len(got[0].Evidence) != 1 {
		t.Fatalf("findings=%+v", got)
	}
	e := got[0].Evidence[0]
	if e.RuleID != "sidebar-html" || e.AssetURL != "" || e.InferredFrom != "" || !reflect.DeepEqual(e.Signals, []detect.Signal{{Source: detect.HTML}, {Source: detect.HTML}, {Source: detect.HTML}}) {
		t.Fatalf("evidence=%+v", e)
	}
	for _, raw := range []string{"16rem", "3rem", "sidebar_state", "private-"} {
		if strings.Contains(e.Description, raw) {
			t.Errorf("raw data in description: %q", e.Description)
		}
	}
}

func TestShadcnSidebarHTML(t *testing.T) {
	engine := bundledEngine(t)
	valid := shadcnWrapper + shadcnInner + shadcnMenu
	cases := map[string]string{
		"fixture":                  string(htmlFixture(t, "shadcn-sidebar.html")),
		"opening-tags":             valid,
		"reversed-groups":          shadcnMenu + shadcnInner + shadcnWrapper,
		"repeated":                 valid + valid,
		"ascii-case":               strings.NewReplacer("<div", "<DIV", "<ul", "<UL", "data-slot=", "DATA-SLOT=", "data-sidebar=", "DATA-SIDEBAR=", "style=", "STYLE=").Replace(valid),
		"other-attributes":         strings.ReplaceAll(valid, "data-slot=", `class="example" hidden data-example='literal attribute' data-slot=`),
		"custom-tags":              strings.NewReplacer("<div", "<app:part", "<ul", "<menu-list").Replace(valid),
		"commented":                "<!-- " + valid + " -->",
		"unrelated-tags":           shadcnWrapper + "</div><section>" + shadcnInner + "</div></section>" + shadcnMenu + "</ul>",
		"custom-values":            strings.ReplaceAll(strings.ReplaceAll(valid, "16rem", "calc(100vw - 8rem)"), "3rem", "var(--custom-size)"),
		"intervening-declarations": strings.Replace(valid, "--sidebar-width:16rem;", "color:red;--sidebar-width:16rem;display:flex;", 1),
		"trailing-declarations":    strings.Replace(valid, "--sidebar-width-icon:3rem", "--sidebar-width-icon:3rem;color:red;", 1),
	}
	for _, quote := range []string{`"`, `'`} {
		for _, reverseStyle := range []bool{false, true} {
			style := "--sidebar-width : 16rem; --sidebar-width-icon : 3rem;"
			if reverseStyle {
				style = "--sidebar-width-icon : 3rem; --sidebar-width : 16rem;"
			}
			for _, reverseAttrs := range []bool{false, true} {
				wrapper := fmt.Sprintf("<div data-slot=%ssidebar-wrapper%s style=%s%s%s>", quote, quote, quote, style, quote)
				inner := fmt.Sprintf("<div data-slot=%ssidebar-inner%s data-sidebar=%ssidebar%s>", quote, quote, quote, quote)
				menu := fmt.Sprintf("<ul data-slot=%ssidebar-menu%s data-sidebar=%smenu%s>", quote, quote, quote, quote)
				if reverseAttrs {
					wrapper = fmt.Sprintf("<div style=%s%s%s\n data-slot=%ssidebar-wrapper%s>", quote, style, quote, quote, quote)
					inner = fmt.Sprintf("<div data-sidebar=%ssidebar%s data-slot=%ssidebar-inner%s>", quote, quote, quote, quote)
					menu = fmt.Sprintf("<ul data-sidebar=%smenu%s data-slot=%ssidebar-menu%s>", quote, quote, quote, quote)
				}
				cases[fmt.Sprintf("quotes=%s/reverse-style=%t/reverse-attrs=%t", quote, reverseStyle, reverseAttrs)] = wrapper + inner + menu
			}
		}
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			input := detect.Input{HTML: []byte(body)}
			got := engine.Detect(input)
			requireShadcn(t, got)
			if !reflect.DeepEqual(got, engine.Detect(input)) {
				t.Fatal("unstable repeat scan")
			}
			got[0].Evidence[0].Signals[0].Source = detect.Header
			requireShadcn(t, engine.Detect(input))
			if got := engine.Detect(detect.Input{}); len(got) != 0 {
				t.Fatalf("retained evidence: %+v", got)
			}
		})
	}
}

func TestShadcnSidebarSubsetsAndStatus(t *testing.T) {
	engine := bundledEngine(t)
	parts := []string{shadcnWrapper, shadcnInner, shadcnMenu}
	for mask := 0; mask < 8; mask++ {
		for _, status := range []int{0, 200, 403, 500} {
			t.Run(fmt.Sprintf("mask=%d/status=%d", mask, status), func(t *testing.T) {
				var body string
				for i, part := range parts {
					if mask&(1<<i) != 0 {
						body += part
					}
				}
				got := engine.Detect(detect.Input{HTTPStatus: status, HTML: []byte(body)})
				if mask == 7 {
					requireShadcn(t, got)
				} else if len(got) != 0 {
					t.Fatalf("findings=%+v", got)
				}
			})
		}
	}
}

func TestShadcnSidebarNearMisses(t *testing.T) {
	engine := bundledEngine(t)
	valid := shadcnWrapper + shadcnInner + shadcnMenu
	cases := map[string]string{
		"generic-slots":          `<button data-slot="button" class="bg-primary">Button</button><div data-slot="card"></div>`,
		"cookie-name":            `sidebar_state`,
		"wrapper-split-tags":     `<div data-slot="sidebar-wrapper"><div style="--sidebar-width:16rem;--sidebar-width-icon:3rem">` + shadcnInner + shadcnMenu,
		"inner-split-tags":       shadcnWrapper + `<div data-slot="sidebar-inner"><div data-sidebar="sidebar">` + shadcnMenu,
		"menu-split-tags":        shadcnWrapper + shadcnInner + `<ul data-slot="sidebar-menu"><ul data-sidebar="menu">`,
		"split-style-attributes": `<div data-slot="sidebar-wrapper" style="--sidebar-width:16rem" style="--sidebar-width-icon:3rem">` + shadcnInner + shadcnMenu,
		"split-style-tags":       `<div data-slot="sidebar-wrapper" style="--sidebar-width:16rem"><div style="--sidebar-width-icon:3rem">` + shadcnInner + shadcnMenu,
		"class-not-style":        strings.Replace(valid, "style=", "class=", 1),
		"width-key-prefix":       strings.Replace(valid, "--sidebar-width:", "--custom-sidebar-width:", 1),
		"width-key-suffix":       strings.Replace(valid, "--sidebar-width:", "--sidebar-width-other:", 1),
		"icon-key-suffix":        strings.Replace(valid, "--sidebar-width-icon:", "--sidebar-width-icon-other:", 1),
		"width-case":             strings.Replace(valid, "--sidebar-width:", "--Sidebar-width:", 1),
		"width-empty":            strings.Replace(valid, "16rem", " ", 1),
		"icon-empty":             strings.Replace(valid, "3rem", " ", 1),
		"missing-semicolon":      strings.Replace(valid, "16rem;", "16rem ", 1),
		"style-name-prefix":      strings.Replace(valid, "style=", "data-style=", 1),
		"slot-name-prefix":       strings.Replace(valid, "data-slot=", "x-data-slot=", 1),
		"slot-name-suffix":       strings.Replace(valid, "data-slot=", "data-slot-other=", 1),
		"entity-value":           strings.Replace(valid, "sidebar-wrapper", "sidebar&#45;wrapper", 1),
		"unquoted-slot":          strings.Replace(valid, `"sidebar-wrapper"`, `sidebar-wrapper`, 1),
		"unquoted-style":         strings.Replace(valid, `style="--sidebar-width:16rem;--sidebar-width-icon:3rem"`, `style=--sidebar-width:16rem;--sidebar-width-icon:3rem`, 1),
		"quoted-example":         `<div data-example="data-slot='sidebar-wrapper' style='--sidebar-width:16rem;--sidebar-width-icon:3rem'">` + shadcnInner + shadcnMenu,
		"escaped-tags":           strings.NewReplacer("<", "&lt;", ">", "&gt;").Replace(valid),
		"not-tags":               strings.ReplaceAll(valid, "<", ""),
	}
	for _, marker := range []string{"sidebar-wrapper", "sidebar-inner", "sidebar-menu"} {
		cases[marker+"-suffix"] = strings.Replace(valid, `"`+marker+`"`, `"`+marker+`-other"`, 1)
		cases[marker+"-case"] = strings.Replace(valid, `"`+marker+`"`, `"`+strings.ToUpper(marker)+`"`, 1)
	}
	for i, part := range []string{shadcnWrapper, shadcnInner, shadcnMenu} {
		cases[fmt.Sprintf("unclosed-tag-%d", i)] = strings.Replace(valid, part, strings.TrimSuffix(part, ">"), 1)
		cases[fmt.Sprintf("quoted-name-%d", i)] = strings.Replace(valid, part, strings.Replace(part, "data-slot=", `"data-slot"=`, 1), 1)
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(detect.Input{HTML: []byte(body)}); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestShadcnSidebarSourceIsolation(t *testing.T) {
	engine := bundledEngine(t)
	valid := shadcnWrapper + shadcnInner + shadcnMenu
	cases := map[string]detect.Input{
		"headers-cookies": {Headers: http.Header{"X-Marker": {valid}}, CookieNames: []string{valid, "sidebar_state"}},
		"javascript":      {Assets: []detect.Asset{scriptAsset("https://example.test/file", valid)}},
		"css":             {Assets: []detect.Asset{cssAsset("https://example.test/file", valid)}},
	}
	for mask := 1; mask < 7; mask++ {
		var page, asset string
		for i, part := range []string{shadcnWrapper, shadcnInner, shadcnMenu} {
			if mask&(1<<i) != 0 {
				page += part
			} else {
				asset += part
			}
		}
		cases[fmt.Sprintf("page-js-%d", mask)] = detect.Input{HTML: []byte(page), Assets: []detect.Asset{scriptAsset("https://example.test/file", asset)}}
		cases[fmt.Sprintf("page-css-%d", mask)] = detect.Input{HTML: []byte(page), Assets: []detect.Asset{cssAsset("https://example.test/file", asset)}}
		cases[fmt.Sprintf("page-header-%d", mask)] = detect.Input{HTML: []byte(page), Headers: http.Header{"X-Marker": {asset}}}
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if got := engine.Detect(input); len(got) != 0 {
				t.Fatalf("findings=%+v", got)
			}
		})
	}
}

func TestShadcnSidebarIndependentTechnologies(t *testing.T) {
	engine := bundledEngine(t)
	for mask := 0; mask < 8; mask++ {
		t.Run(fmt.Sprint(mask), func(t *testing.T) {
			input := detect.Input{}
			var ids []string
			if mask&1 != 0 {
				input.Assets = append(input.Assets, scriptAsset("https://example.test/runtime", radixObject(radixMappings("popover"))))
				ids = append(ids, "radix-ui")
			}
			if mask&2 != 0 {
				input.HTML = []byte(shadcnWrapper + shadcnInner + shadcnMenu)
				ids = append(ids, "shadcn-ui")
			}
			if mask&4 != 0 {
				input.Assets = append(input.Assets, cssAsset("https://example.test/styles", tailwind3Banner+tailwind3Preflight))
				ids = append(ids, "tailwindcss")
			}
			got := engine.Detect(input)
			var gotIDs []string
			for _, f := range got {
				gotIDs = append(gotIDs, f.ID)
				if f.State != detect.Inferred {
					t.Fatalf("finding=%+v", f)
				}
			}
			if !reflect.DeepEqual(gotIDs, ids) {
				t.Fatalf("findings=%+v want=%v", got, ids)
			}
		})
	}
}
