package detect

import (
	"bytes"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

//go:embed fingerprints/*.json
var bundled embed.FS

var (
	identifier = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)
	headerName = regexp.MustCompile("^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
)

func LoadBundled() (*Engine, error) {
	root, err := fs.Sub(bundled, "fingerprints")
	if err != nil {
		return nil, err
	}
	return Load(root)
}

// Load reads versioned JSON catalogs from the filesystem's root. Cross-file
// references are resolved after all files have been loaded and validated.
func Load(root fs.FS) (*Engine, error) {
	paths, err := fs.Glob(root, "*.json")
	if err != nil {
		return nil, fmt.Errorf("list fingerprints: %w", err)
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no fingerprint JSON files found")
	}
	engine := &Engine{byID: make(map[string]*compiledTechnology)}
	for _, path := range paths {
		data, err := fs.ReadFile(root, path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		var document catalog
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&document); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if err := decoder.Decode(new(any)); err != io.EOF {
			return nil, fmt.Errorf("%s: expected a single JSON document", path)
		}
		if document.SchemaVersion != 1 {
			return nil, fmt.Errorf("%s: unsupported schema_version %d", path, document.SchemaVersion)
		}
		if document.Technologies == nil {
			return nil, fmt.Errorf("%s: technologies must be an array", path)
		}
		for _, tech := range document.Technologies {
			if _, exists := engine.byID[tech.ID]; exists {
				return nil, fmt.Errorf("%s: duplicate technology ID %q", path, tech.ID)
			}
			compiled, err := compileTechnology(tech)
			if err != nil {
				return nil, fmt.Errorf("%s: technology %q: %w", path, tech.ID, err)
			}
			engine.byID[tech.ID] = compiled
			engine.technologies = append(engine.technologies, compiled)
		}
	}
	sort.Slice(engine.technologies, func(i, j int) bool {
		return engine.technologies[i].id < engine.technologies[j].id
	})
	if err := engine.validateRelationships(); err != nil {
		return nil, err
	}
	return engine, nil
}

func compileTechnology(tech technology) (*compiledTechnology, error) {
	if !identifier.MatchString(tech.ID) || strings.TrimSpace(tech.Name) == "" {
		return nil, fmt.Errorf("a lowercase hyphenated ID and nonempty name are required")
	}
	switch tech.Category {
	case Framework, WebServer, Language, CMS, CDN, LoadBalancer, WAF:
	default:
		return nil, fmt.Errorf("unknown category %q", tech.Category)
	}
	compiled := &compiledTechnology{id: tech.ID, name: tech.Name, category: tech.Category, implies: tech.Implies}
	seenRules := make(map[string]bool)
	for _, r := range tech.Rules {
		if !identifier.MatchString(r.ID) || seenRules[r.ID] {
			return nil, fmt.Errorf("invalid or duplicate rule ID %q", r.ID)
		}
		seenRules[r.ID] = true
		if r.State != Detected && r.State != Inferred {
			return nil, fmt.Errorf("rule %q: state must be detected or inferred", r.ID)
		}
		if strings.TrimSpace(r.Description) == "" || len(r.All) == 0 {
			return nil, fmt.Errorf("rule %q: description and at least one all matcher are required", r.ID)
		}
		cr := compiledRule{id: r.ID, state: r.State, description: r.Description}
		for _, m := range r.All {
			switch m.Source {
			case Header:
				if !headerName.MatchString(m.Name) {
					return nil, fmt.Errorf("rule %q: header matcher needs a valid name", r.ID)
				}
				m.Name = http.CanonicalHeaderKey(m.Name)
				if m.Name == "Set-Cookie" || m.Name == "Cookie" {
					return nil, fmt.Errorf("rule %q: use cookie-name matchers instead of cookie headers", r.ID)
				}
			case Cookie, HTML:
				if m.Name != "" {
					return nil, fmt.Errorf("rule %q: name is only valid for header matchers", r.ID)
				}
			default:
				return nil, fmt.Errorf("rule %q: unknown source %q", r.ID, m.Source)
			}
			pattern, err := regexp.Compile(m.Pattern)
			if err != nil {
				return nil, fmt.Errorf("rule %q: invalid pattern: %w", r.ID, err)
			}
			if pattern.MatchString("") {
				return nil, fmt.Errorf("rule %q: patterns must not match empty input", r.ID)
			}
			cr.matchers = append(cr.matchers, compiledMatcher{source: m.Source, name: m.Name, pattern: pattern})
		}
		compiled.rules = append(compiled.rules, cr)
	}
	sort.Slice(compiled.rules, func(i, j int) bool { return compiled.rules[i].id < compiled.rules[j].id })
	sort.Strings(compiled.implies)
	return compiled, nil
}

func (e *Engine) validateRelationships() error {
	incoming := make(map[string]bool)
	for _, tech := range e.technologies {
		seen := make(map[string]bool)
		for _, id := range tech.implies {
			if _, exists := e.byID[id]; !exists {
				return fmt.Errorf("technology %q implies unknown technology %q", tech.id, id)
			}
			if seen[id] {
				return fmt.Errorf("technology %q has duplicate implication %q", tech.id, id)
			}
			seen[id], incoming[id] = true, true
		}
	}
	// 1 = visiting, 2 = complete. Cycles are catalog errors, not runtime guesses.
	visited := make(map[string]int)
	var visit func(string) error
	visit = func(id string) error {
		if visited[id] == 1 {
			return fmt.Errorf("inference cycle at technology %q", id)
		}
		if visited[id] == 2 {
			return nil
		}
		visited[id] = 1
		for _, next := range e.byID[id].implies {
			if err := visit(next); err != nil {
				return err
			}
		}
		visited[id] = 2
		return nil
	}
	for _, tech := range e.technologies {
		if len(tech.rules) == 0 && !incoming[tech.id] {
			return fmt.Errorf("technology %q needs a rule or an incoming inference", tech.id)
		}
		if err := visit(tech.id); err != nil {
			return err
		}
	}
	return nil
}
