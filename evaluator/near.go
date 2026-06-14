package evaluator

import (
	"path"
	"sync"
	"time"

	"github.com/doracpphp/sigma-go"
)

// nearMatchState records, per search identifier, the last time it matched an
// event. It backs the legacy `near` aggregation, which fires when the searches in
// its expression have all matched within the rule's timeframe.
type nearMatchState struct {
	mu        sync.Mutex
	lastMatch map[string]time.Time
}

// evaluateNear implements the `near` aggregation (e.g. `selection | near filter`).
// The match times of the referenced searches are recorded by the caller for every
// event; here we evaluate the near expression treating an identifier as "true" if
// it last matched within the rule's timeframe (ending at now).
func (rule RuleEvaluator) evaluateNear(near sigma.Near, now time.Time) bool {
	rule.nearState.mu.Lock()
	defer rule.nearState.mu.Unlock()

	timeframe := rule.Detection.Timeframe
	withinTimeframe := func(id string) bool {
		last, ok := rule.nearState.lastMatch[id]
		if !ok {
			return false
		}
		if timeframe <= 0 {
			// No timeframe configured: any prior match counts.
			return true
		}
		return !last.Before(now.Add(-timeframe))
	}

	return rule.evaluateSearchExpression(near.Condition, withinTimeframe)
}

// collectIdentifiers returns all search identifier names referenced by a search
// expression, expanding `1/all of them` and patterns against the rule's searches.
func collectIdentifiers(expr sigma.SearchExpr, searches map[string]sigma.Search) []string {
	set := map[string]bool{}
	var walk func(e sigma.SearchExpr)
	walk = func(e sigma.SearchExpr) {
		switch s := e.(type) {
		case sigma.And:
			for _, n := range s {
				walk(n)
			}
		case sigma.Or:
			for _, n := range s {
				walk(n)
			}
		case sigma.Not:
			walk(s.Expr)
		case sigma.SearchIdentifier:
			set[s.Name] = true
		case sigma.OneOfIdentifier:
			set[s.Ident.Name] = true
		case sigma.AllOfIdentifier:
			set[s.Ident.Name] = true
		case sigma.OneOfThem, sigma.AllOfThem:
			for name := range searches {
				set[name] = true
			}
		case sigma.OneOfPattern:
			for name := range searches {
				if matched, _ := path.Match(s.Pattern, name); matched {
					set[name] = true
				}
			}
		case sigma.AllOfPattern:
			for name := range searches {
				if matched, _ := path.Match(s.Pattern, name); matched {
					set[name] = true
				}
			}
		}
	}
	walk(expr)

	out := make([]string, 0, len(set))
	for name := range set {
		out = append(out, name)
	}
	return out
}
