package detect

import (
	"fmt"
	"regexp"
	"strings"
)

// Engine is immutable after loading and can be reused across scans.
type Engine struct {
	technologies []*compiledTechnology
	byID         map[string]*compiledTechnology
}

type compiledTechnology struct {
	id, name string
	category Category
	rules    []compiledRule
	implies  []string
}

type compiledRule struct {
	id, description string
	state           State
	matchers        []compiledMatcher
}

type compiledMatcher struct {
	source  Source
	name    string
	pattern *regexp.Regexp
}

func (e *Engine) Len() int { return len(e.technologies) }

// Detect requires every matcher in a rule, and accepts any matching rule in a
// technology. Direct detections take precedence over inferences. Results are
// sorted by technology ID, and evidence never includes raw response values.
func (e *Engine) Detect(input Input) []Finding {
	headers := make(map[string][]string, len(input.Headers))
	for name, values := range input.Headers {
		key := strings.ToLower(name)
		headers[key] = append(headers[key], values...)
	}
	found := make(map[string]*Finding)
	var queue []string
	for _, tech := range e.technologies {
		for _, rule := range tech.rules {
			if !rule.matches(input, headers) {
				continue
			}
			finding, exists := found[tech.id]
			if !exists {
				finding = &Finding{ID: tech.id, Name: tech.name, Category: tech.category, State: rule.state}
				found[tech.id] = finding
				queue = append(queue, tech.id)
			}
			if rule.state == Detected {
				finding.State = Detected
			}
			evidence := Evidence{RuleID: rule.id, Description: rule.description}
			for _, matcher := range rule.matchers {
				evidence.Signals = append(evidence.Signals, Signal{Source: matcher.source, Name: matcher.name})
			}
			finding.Evidence = append(finding.Evidence, evidence)
		}
	}
	// Each technology is queued once. Keep every supporting inference edge,
	// including when a target already has direct evidence or another parent.
	for i := 0; i < len(queue); i++ {
		parent := e.byID[queue[i]]
		for _, id := range parent.implies {
			finding, exists := found[id]
			if !exists {
				tech := e.byID[id]
				finding = &Finding{ID: id, Name: tech.name, Category: tech.category, State: Inferred}
				found[id] = finding
				queue = append(queue, id)
			}
			finding.Evidence = append(finding.Evidence, Evidence{
				Description:  fmt.Sprintf("Inferred from %s", parent.name),
				InferredFrom: parent.id,
			})
		}
	}
	results := make([]Finding, 0, len(found))
	for _, tech := range e.technologies {
		if finding, exists := found[tech.id]; exists {
			results = append(results, *finding)
		}
	}
	return results
}

func (r compiledRule) matches(input Input, headers map[string][]string) bool {
	for _, matcher := range r.matchers {
		var matched bool
		switch matcher.source {
		case Header:
			matched = matchesAny(matcher.pattern, headers[strings.ToLower(matcher.name)])
		case Cookie:
			matched = matchesAny(matcher.pattern, input.CookieNames)
		case HTML:
			matched = matcher.pattern.Match(input.HTML)
		}
		if !matched {
			return false
		}
	}
	return true
}

func matchesAny(pattern *regexp.Regexp, values []string) bool {
	for _, value := range values {
		if pattern.MatchString(value) {
			return true
		}
	}
	return false
}
