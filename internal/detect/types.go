// Package detect matches captured page signals without performing network I/O.
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
)

type Source string

const (
	Header Source = "header"
	Cookie Source = "cookie"
	HTML   Source = "html"
)

// Input contains only final-response signals. HTML is populated by the caller
// for HTML documents, not arbitrary response bodies or redirect pages.
type Input struct {
	Headers     http.Header
	CookieNames []string
	HTML        []byte
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
