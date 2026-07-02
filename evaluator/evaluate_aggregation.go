package evaluator

import (
	"context"
	"fmt"
	"strconv"

	"github.com/doracpphp/sigma-go"
)

func (rule RuleEvaluator) evaluateAggregationExpression(ctx context.Context, conditionIndex int, aggregation sigma.AggregationExpr, event Event) (bool, error) {
	switch agg := aggregation.(type) {
	case sigma.Near:
		return false, fmt.Errorf("near isn't supported yet")

	case sigma.Comparison:
		aggregationValue, err := rule.evaluateAggregationFunc(ctx, conditionIndex, agg.Func, event)
		if err != nil {
			return false, err
		}
		switch agg.Op {
		case sigma.Equal:
			return aggregationValue == agg.Threshold, nil
		case sigma.NotEqual:
			return aggregationValue != agg.Threshold, nil
		case sigma.LessThan:
			return aggregationValue < agg.Threshold, nil
		case sigma.LessThanEqual:
			return aggregationValue <= agg.Threshold, nil
		case sigma.GreaterThan:
			return aggregationValue > agg.Threshold, nil
		case sigma.GreaterThanEqual:
			return aggregationValue >= agg.Threshold, nil
		default:
			return false, fmt.Errorf("unsupported comparison operation %v", agg.Op)
		}

	default:
		return false, fmt.Errorf("unknown aggregation expression")
	}
}

// groupByValues collects the values of each group-by field from the event. The
// resulting map uniquely identifies an aggregation bucket (see GroupedByValues).
func groupByValues(event Event, fields []string) map[string]interface{} {
	values := make(map[string]interface{}, len(fields))
	for _, field := range fields {
		values[field] = eventValue(event, field)
	}
	return values
}

func (rule RuleEvaluator) evaluateAggregationFunc(ctx context.Context, conditionIndex int, aggregation sigma.AggregationFunc, event Event) (float64, error) {
	switch agg := aggregation.(type) {
	case sigma.Count:
		if agg.Field == "" {
			// This is a simple count number of events
			if rule.count == nil {
				return 0, fmt.Errorf("rule uses count() but no count implementation was provided (see evaluator.CountImplementation)")
			}
			return rule.count(ctx, rule.groupedBy(conditionIndex, event, agg.GroupedBy))
		} else {
			// This is a more complex, count distinct values for a field
			// e.g. `count(TargetUserName) by IpAddress` counts the number of
			// distinct TargetUserName values seen per IpAddress (password spray).
			if rule.countDistinct == nil {
				return 0, fmt.Errorf("rule uses count(%s) but no count-distinct implementation was provided (see evaluator.CountDistinctImplementation)", agg.Field)
			}
			return rule.countDistinct(ctx, rule.groupedBy(conditionIndex, event, agg.GroupedBy), eventValue(event, agg.Field))
		}

	case sigma.Average:
		if rule.average == nil {
			return 0, fmt.Errorf("rule uses avg(%s) but no average implementation was provided (see evaluator.AverageImplementation)", agg.Field)
		}
		val, err := strconv.ParseFloat(fmt.Sprint(eventValue(event, agg.Field)), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid float value: %w", err)
		}
		return rule.average(ctx, rule.groupedBy(conditionIndex, event, agg.GroupedBy), val)

	case sigma.Sum:
		if rule.sum == nil {
			return 0, fmt.Errorf("rule uses sum(%s) but no sum implementation was provided (see evaluator.SumImplementation)", agg.Field)
		}
		val, err := strconv.ParseFloat(fmt.Sprint(eventValue(event, agg.Field)), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid float value: %w", err)
		}
		return rule.sum(ctx, rule.groupedBy(conditionIndex, event, agg.GroupedBy), val)

	case sigma.Min:
		if rule.min == nil {
			return 0, fmt.Errorf("rule uses min(%s) but no min implementation was provided (see evaluator.MinImplementation)", agg.Field)
		}
		val, err := strconv.ParseFloat(fmt.Sprint(eventValue(event, agg.Field)), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid float value: %w", err)
		}
		return rule.min(ctx, rule.groupedBy(conditionIndex, event, agg.GroupedBy), val)

	case sigma.Max:
		if rule.max == nil {
			return 0, fmt.Errorf("rule uses max(%s) but no max implementation was provided (see evaluator.MaxImplementation)", agg.Field)
		}
		val, err := strconv.ParseFloat(fmt.Sprint(eventValue(event, agg.Field)), 64)
		if err != nil {
			return 0, fmt.Errorf("invalid float value: %w", err)
		}
		return rule.max(ctx, rule.groupedBy(conditionIndex, event, agg.GroupedBy), val)

	default:
		return 0, fmt.Errorf("unsupported aggregation function")
	}
}

// aggregationRuleID identifies the rule in aggregation bucket keys, so distinct
// rules never share aggregation state even when they are evaluated through one
// shared aggregator implementation.
func (rule RuleEvaluator) aggregationRuleID() string {
	switch {
	case rule.ID != "":
		return rule.ID
	case rule.Name != "":
		return rule.Name
	default:
		return rule.Title
	}
}

// groupedBy builds the aggregation bucket identity for one condition of this
// rule evaluated against one event.
func (rule RuleEvaluator) groupedBy(conditionIndex int, event Event, fields []string) GroupedByValues {
	return GroupedByValues{
		RuleID:      rule.aggregationRuleID(),
		ConditionID: conditionIndex,
		EventValues: groupByValues(event, fields),
		Timeframe:   rule.Detection.Timeframe,
	}
}
