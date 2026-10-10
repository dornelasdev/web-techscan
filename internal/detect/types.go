// Package detect matches captured page and asset signals without network I/O.
package detect

import "net/http"

type State string

const (
	Detected State = "detected"
	Inferred State = "inferred"
)

type Category string

const (
	Framework    Category = "framework"
	WebServer    Category = "web_server"
	Language     Category = "language"
	CMS          Category = "cms"
	CDN          Category = "cdn"
	LoadBalancer Category = "load_balancer"
	WAF          Category = "waf"
)

type Source string

const (
	Header          Source = "header"
	Cookie          Source = "cookie"
	HTML            Source = "html"
	AssetJavaScript Source = "asset_javascript"
	AssetCSS        Source = "asset_css"
)

// Input keeps final-page signals separate from successfully collected assets.
// HTML is populated only for HTML documents, never asset or redirect bodies.
type Input struct {
	Headers     http.Header
	CookieNames []string
	HTML        []byte
	Assets      []Asset
}

// Asset is one complete, MIME-validated captured body, not an executed script.
// The caller owns selection/fetching. Source must be AssetJavaScript or AssetCSS.
type Asset struct {
	URL    string
	Source Source
	Body   []byte
}

type Finding struct {
	ID       string
	Name     string
	Category Category
	State    State
	Evidence []Evidence
}

// TechnologyInfo describes catalog coverage, not a finding from a scan.
type TechnologyInfo struct {
	ID       string
	Name     string
	Category Category
}

// Evidence describes the rule and signal locations, without copying response
// content or cookie values into results. InferredFrom is a technology ID.
type Evidence struct {
	RuleID       string
	Description  string
	Signals      []Signal
	InferredFrom string
	AssetURL     string // Present only for a rule matched within this one asset.
}

type Signal struct {
	Source Source
	Name   string
}

type catalog struct {
	SchemaVersion int          `json:"schema_version"`
	Technologies  []technology `json:"technologies"`
}

type technology struct {
	ID       string   `json:"id"`
	Name     string   `json:"name"`
	Category Category `json:"category"`
	Rules    []rule   `json:"rules"`
	Implies  []string `json:"implies"`
}

type rule struct {
	ID          string    `json:"id"`
	State       State     `json:"state"`
	Description string    `json:"description"`
	All         []matcher `json:"all"`
}

type matcher struct {
	Source  Source `json:"source"`
	Name    string `json:"name"`
	Pattern string `json:"pattern"`
}
