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
	assetSource     Source // Empty for page rules; otherwise all matchers share it.
}

type compiledMatcher struct {
	source  Source
	name    string
	pattern *regexp.Regexp
}

func (e *Engine) Len() int { return len(e.technologies) }

// Technologies returns independent catalog metadata sorted by technology ID,
// including technologies supported only through inference relationships.
func (e *Engine) Technologies() []TechnologyInfo {
	items := make([]TechnologyInfo, 0, len(e.technologies))
	for _, tech := range e.technologies {
		items = append(items, TechnologyInfo{ID: tech.id, Name: tech.name, Category: tech.category})
	}
	return items
}

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
			evidence := rule.evidence(input, headers)
			if len(evidence) == 0 {
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
			finding.Evidence = append(finding.Evidence, evidence...)
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

func (r compiledRule) evidence(input Input, headers map[string][]string) []Evidence {
	makeEvidence := func(url string) Evidence {
		item := Evidence{RuleID: r.id, Description: r.description, AssetURL: url}
		for _, matcher := range r.matchers {
			item.Signals = append(item.Signals, Signal{Source: matcher.source, Name: matcher.name})
		}
		return item
	}
	if r.assetSource == "" {
		if r.matches(input, headers, nil) {
			return []Evidence{makeEvidence("")}
		}
		return nil
	}
	var result []Evidence
	seen := make(map[string]bool)
	for _, asset := range input.Assets {
		if asset.Source != r.assetSource || asset.URL == "" || seen[asset.URL] {
			continue
		}
		// All conditions must match this body, never a concatenation or a
		// pair split across files. Input order preserves collection order.
		if r.matches(input, headers, asset.Body) {
			seen[asset.URL] = true
			result = append(result, makeEvidence(asset.URL))
		}
	}
	return result
}

func (r compiledRule) matches(input Input, headers map[string][]string, assetBody []byte) bool {
	for _, matcher := range r.matchers {
		var matched bool
		switch matcher.source {
		case Header:
			matched = matchesAny(matcher.pattern, headers[strings.ToLower(matcher.name)])
		case Cookie:
			matched = matchesAny(matcher.pattern, input.CookieNames)
		case HTML:
			matched = matcher.pattern.Match(input.HTML)
		case AssetJavaScript, AssetCSS:
			matched = matcher.pattern.Match(assetBody)
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
