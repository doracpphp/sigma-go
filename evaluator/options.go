package evaluator

import (
	"context"
	"github.com/doracpphp/sigma-go/evaluator/modifiers"

	"github.com/doracpphp/sigma-go"
)

type Option func(*RuleEvaluator)

func CountImplementation(count func(ctx context.Context, key GroupedByValues) (float64, error)) Option {
	return func(e *RuleEvaluator) {
		e.count = count
	}
}

// CountDistinctImplementation provides the implementation for the count-distinct
// aggregation (e.g. `count(TargetUserName) by IpAddress`). For each event it is
// passed the group key and the value of the counted field, and must return the
// number of distinct values seen for that group within the rule's timeframe.
func CountDistinctImplementation(countDistinct func(ctx context.Context, key GroupedByValues, value interface{}) (float64, error)) Option {
	return func(e *RuleEvaluator) {
		e.countDistinct = countDistinct
	}
}

func SumImplementation(sum func(ctx context.Context, key GroupedByValues, value float64) (float64, error)) Option {
	return func(e *RuleEvaluator) {
		e.sum = sum
	}
}

func AverageImplementation(average func(ctx context.Context, key GroupedByValues, value float64) (float64, error)) Option {
	return func(e *RuleEvaluator) {
		e.average = average
	}
}

// MinImplementation provides the implementation for the min aggregation
// (e.g. `min(FileSize) by Host`). For each event it is passed the group key
// and the value of the aggregated field, and must return the minimum value
// seen for that group within the rule's timeframe.
func MinImplementation(min func(ctx context.Context, key GroupedByValues, value float64) (float64, error)) Option {
	return func(e *RuleEvaluator) {
		e.min = min
	}
}

// MaxImplementation provides the implementation for the max aggregation
// (e.g. `max(FileSize) by Host`). For each event it is passed the group key
// and the value of the aggregated field, and must return the maximum value
// seen for that group within the rule's timeframe.
func MaxImplementation(max func(ctx context.Context, key GroupedByValues, value float64) (float64, error)) Option {
	return func(e *RuleEvaluator) {
		e.max = max
	}
}

func WithPlaceholderExpander(f func(ctx context.Context, placeholderName string) ([]string, error)) Option {
	return func(e *RuleEvaluator) {
		e.expandPlaceholder = f
	}
}

func WithConfig(config ...sigma.Config) Option {
	return func(e *RuleEvaluator) {
		// TODO: assert that the configs are in the correct order
		e.config = append(e.config, config...)
		e.calculateIndexes()
		e.calculateFieldMappings()
	}
}

// CaseSensitive turns off the default Sigma behaviour that string operations are by default case-insensitive
// This can increase performance (especially for larger events) by skipping expensive calls to strings.ToLower
func CaseSensitive(e *RuleEvaluator) {
	e.caseSensitive = true
	e.comparators = modifiers.ComparatorsCaseSensitive
}

// LazyEvaluation allows the evaluator to skip evaluating searches if they won't affect the overall match result
func LazyEvaluation(e *RuleEvaluator) {
	e.lazy = true
}
