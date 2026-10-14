package detect

// CategoryInfo is static catalog organization, not observed scan evidence.
// Group is a terminal heading; it is not a fingerprint or JSON report field.
type CategoryInfo struct {
	Group   string
	Label   string
	Heading string
	Order   int
}

// Keep categories in display order, with each group's categories contiguous.
var categoryMetadata = [...]struct {
	category Category
	info     CategoryInfo
}{
	{Framework, CategoryInfo{Group: "Web development", Label: "framework", Heading: "Web frameworks"}},
	{JSFramework, CategoryInfo{Group: "Web development", Label: "JavaScript framework", Heading: "JavaScript frameworks"}},
	{UIFramework, CategoryInfo{Group: "Web development", Label: "UI framework", Heading: "UI frameworks"}},
	{CMS, CategoryInfo{Group: "Web development", Label: "CMS", Heading: "CMS"}},
	{Language, CategoryInfo{Group: "Web development", Label: "language", Heading: "Languages"}},
	{WebServer, CategoryInfo{Group: "Infrastructure", Label: "web server", Heading: "Web servers"}},
	{CDN, CategoryInfo{Group: "Infrastructure", Label: "CDN/edge", Heading: "CDN/edge"}},
	{LoadBalancer, CategoryInfo{Group: "Infrastructure", Label: "load balancer", Heading: "Load balancers"}},
	{WAF, CategoryInfo{Group: "Infrastructure", Label: "WAF", Heading: "WAFs"}},
}

// Info returns a value copy of the category's metadata. Unknown categories are
// invalid in fingerprint catalogs but can be preserved by output consumers.
func (c Category) Info() (CategoryInfo, bool) {
	for i, entry := range categoryMetadata {
		if entry.category == c {
			info := entry.info
			info.Order = i
			return info, true
		}
	}
	return CategoryInfo{Group: "Other", Label: string(c), Heading: string(c), Order: len(categoryMetadata)}, false
}
