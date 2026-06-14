package evaluator

import (
	"context"
	"fmt"
	"path"
	"strings"

	"github.com/doracpphp/sigma-go"
)

// RelevantToIndex calculates whether this rule is applicable to a given index.
// Only applicable if a config file has been loaded otherwise it always returns false.
func (rule *RuleEvaluator) calculateIndexes() {
	if rule.config == nil {
		return
	}

	var indexes []string

	category := rule.Logsource.Category
	product := rule.Logsource.Product
	service := rule.Logsource.Service

	for _, config := range rule.config {
		if config.LogsourceMerging == sigma.LogsourceMergeOr {
			rule.logsourceMerging = sigma.LogsourceMergeOr
		}
		matched := false
		for _, logsource := range config.Logsources {
			// If this mapping is not relevant, skip it
			switch {
			case logsource.Category != "" && logsource.Category != category:
				continue
			case logsource.Product != "" && logsource.Product != product:
				continue
			case logsource.Service != "" && logsource.Service != service:
				continue
			}

			matched = true
			// LogsourceMappings can specify rewrite rules that change the effective Category, Product, and Service of a rule.
			// These then get interpreted by later configs.
			if logsource.Rewrite.Category != "" {
				category = logsource.Rewrite.Category
			}
			if logsource.Rewrite.Product != "" {
				product = logsource.Rewrite.Product
			}
			if logsource.Rewrite.Service != "" {
				service = logsource.Rewrite.Service
			}

			// If the mapping has indexes then append them to the possible ones
			indexes = append(indexes, logsource.Index...)

			// If the mapping declares (non-empty) conditions then add them. Empty
			// conditions are skipped: they match everything and so are no-ops under
			// "and" merging and would wrongly make "or" merging always true.
			if len(logsource.Conditions.EventMatchers) > 0 || len(logsource.Conditions.Keywords) > 0 {
				rule.indexConditions = append(rule.indexConditions, logsource.Conditions)
			}
		}

		if !matched && config.DefaultIndex != "" {
			indexes = append(indexes, config.DefaultIndex)
		}
	}

	rule.indexes = indexes
}

func (rule RuleEvaluator) Indexes() []string {
	return rule.indexes
}

// RelevantToEvent calculates whether a rule is applicable to an event based on:
//   - Whether the rule has been configured with a config file that matches the eventIndex
//   - Whether the event matches the conditions from the config file
func (rule RuleEvaluator) RelevantToEvent(ctx context.Context, eventIndex string, event Event) (bool, error) {
	matchedIndex := false
	for _, index := range rule.indexes {
		if indexMatches(index, eventIndex) {
			matchedIndex = true
			break
		}
	}
	if !matchedIndex {
		return false, nil
	}

	// The event *does* come from an index we're interested in but we still need to
	// check for any value constraints that have been specified. How multiple
	// conditions are combined is controlled by the config's logsourcemerging option.
	if len(rule.indexConditions) == 0 {
		return true, nil
	}

	if rule.logsourceMerging == sigma.LogsourceMergeOr {
		for _, condition := range rule.indexConditions {
			searchMatches, err := rule.evaluateSearch(ctx, condition, event, rule.comparators)
			if err != nil {
				return false, fmt.Errorf("failed to evaluate index condition: %w", err)
			}
			if searchMatches {
				return true, nil
			}
		}
		return false, nil
	}

	// Default: "and" merging - every condition must match.
	for _, condition := range rule.indexConditions {
		searchMatches, err := rule.evaluateSearch(ctx, condition, event, rule.comparators)
		if err != nil {
			return false, fmt.Errorf("failed to evaluate index condition: %w", err)
		}
		if !searchMatches {
			return false, nil
		}
	}
	return true, nil
}

// indexMatches reports whether an index pattern from a config matches a concrete
// event index. Patterns may contain `*`/`?` wildcards (e.g. `logs-*`).
func indexMatches(pattern, index string) bool {
	if !strings.ContainsAny(pattern, "*?") {
		return pattern == index
	}
	matched, err := path.Match(pattern, index)
	return err == nil && matched
}
