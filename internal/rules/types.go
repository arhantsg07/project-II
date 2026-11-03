// Package rules loads and evaluates a small, Sigma-inspired set of event rules.
package rules

// MatchContext is the rule-visible projection of one normalized event.
type MatchContext struct {
	EventID       int64
	EventType     string
	Outcome       string
	Host          string
	User          string
	Process       string
	ParentProcess string
	SrcIP         string
	Domain        string
	DomainEntropy float64
	Fields        map[string]interface{}
	EntityIDs     map[string]string
}

// Selection is one AND-of-conditions clause. A rule's selections are OR'd.
type Selection map[string]interface{}

// Aggregation adds a count threshold over events matching the rule's event type.
type Aggregation struct {
	GroupBy  string `yaml:"group_by"`
	Window   string `yaml:"window"`
	CountGTE int    `yaml:"count_gte"`
}

// Rule describes one detection, including its metadata and matching clauses.
type Rule struct {
	ID          string       `yaml:"id"`
	Title       string       `yaml:"title"`
	Description string       `yaml:"description"`
	Attack      []string     `yaml:"attack"`
	Severity    string       `yaml:"severity"`
	Detection   []Selection  `yaml:"detection"`
	Aggregation *Aggregation `yaml:"aggregation,omitempty"`
}

// Matches reports whether any selection matches this event.
func (r Rule) Matches(ctx MatchContext) bool {
	for _, selection := range r.Detection {
		if selectionMatches(selection, ctx) {
			return true
		}
	}
	return false
}
