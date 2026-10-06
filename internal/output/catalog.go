package output

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"webscan/internal/detect"
)

// CatalogReport is the --techs JSON contract, separate from scan reports.
type CatalogReport struct {
	SchemaVersion int          `json:"schema_version"`
	CatalogSize   int          `json:"catalog_size"`
	Technologies  []Technology `json:"technologies"`
}

type Technology struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Category string `json:"category"`
}

func NewCatalogReport(items []detect.TechnologyInfo) CatalogReport {
	report := CatalogReport{SchemaVersion: 1, CatalogSize: len(items), Technologies: make([]Technology, 0, len(items))}
	for _, item := range items {
		report.Technologies = append(report.Technologies, Technology{ID: item.ID, Name: item.Name, Category: string(item.Category)})
	}
	sort.Slice(report.Technologies, func(i, j int) bool {
		a, b := report.Technologies[i], report.Technologies[j]
		if categoryOrder(a.Category) != categoryOrder(b.Category) {
			return categoryOrder(a.Category) < categoryOrder(b.Category)
		}
		if a.Category != b.Category {
			return a.Category < b.Category
		}
		if strings.ToLower(a.Name) != strings.ToLower(b.Name) {
			return strings.ToLower(a.Name) < strings.ToLower(b.Name)
		}
		return a.ID < b.ID
	})
	return report
}

func categoryOrder(category string) int {
	switch category {
	case "web_server":
		return 0
	case "framework":
		return 1
	case "cms":
		return 2
	case "language":
		return 3
	default:
		return 4
	}
}

func CatalogJSON(w io.Writer, report CatalogReport) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	return write(w, append(data, '\n'))
}

// CatalogTerminal renders the ordered catalog without scan states or color.
func CatalogTerminal(w io.Writer, report CatalogReport) error {
	var text strings.Builder
	fmt.Fprintf(&text, "Supported technologies (%d)\n", report.CatalogSize)
	lastCategory := ""
	for i, tech := range report.Technologies {
		if i == 0 || tech.Category != lastCategory {
			title := tech.Category
			switch tech.Category {
			case "web_server":
				title = "Web servers"
			case "framework":
				title = "Frameworks"
			case "cms":
				title = "CMS"
			case "language":
				title = "Languages"
			}
			fmt.Fprintf(&text, "\n%s\n", plain(title))
			lastCategory = tech.Category
		}
		fmt.Fprintf(&text, "  %s\n", plain(tech.Name))
	}
	if len(report.Technologies) == 0 {
		fmt.Fprintln(&text, "\nNo technologies bundled.")
	}
	fmt.Fprintln(&text, "\nCoverage depends on exposed signals; identification is not guaranteed.")
	return write(w, []byte(text.String()))
}
