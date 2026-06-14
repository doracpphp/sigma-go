package sigma

import (
	"fmt"
	"strconv"
	"time"

	"gopkg.in/yaml.v3"
)

// Correlation rule types.
const (
	CorrelationEventCount      = "event_count"
	CorrelationValueCount      = "value_count"
	CorrelationTemporal        = "temporal"
	CorrelationTemporalOrdered = "temporal_ordered"
)

// Correlation describes a Sigma correlation rule: a meta-rule that aggregates the
// matches of one or more referenced rules over a sliding time window.
//
// See https://github.com/SigmaHQ/sigma-specification (Sigma Correlation Rules).
type Correlation struct {
	// Type is one of event_count, value_count, temporal, temporal_ordered.
	Type string `yaml:",omitempty" json:",omitempty"`

	// Rules references the correlated rules by their `name` or `id`.
	Rules []string `yaml:",omitempty" json:",omitempty"`

	// GroupBy lists the fields whose values partition events into independent
	// correlation buckets (parsed from the `group-by` key).
	GroupBy []string `yaml:"group-by,omitempty" json:"group-by,omitempty"`

	// Timespan is the sliding window over which the correlation is evaluated.
	Timespan Timespan `yaml:",omitempty" json:",omitempty"`

	// Aliases optionally maps a group-by alias to the concrete field name used by
	// each referenced rule: aliases[alias][ruleNameOrID] = fieldName.
	Aliases map[string]map[string]string `yaml:",omitempty" json:",omitempty"`

	// Condition holds the threshold for event_count / value_count correlations.
	Condition *CorrelationCondition `yaml:",omitempty" json:",omitempty"`
}

// CorrelationCondition is the threshold comparison for event_count / value_count
// correlation rules, e.g. `{gte: 10}` or, for value_count, `{gte: 100, field: User}`.
type CorrelationCondition struct {
	// Op is one of gt, gte, lt, lte, eq, neq.
	Op string
	// Count is the threshold the (event or value) count is compared against.
	Count int
	// Field is the field whose distinct values are counted (value_count only).
	Field string
}

// Timespan is a Sigma correlation timespan such as `30s`, `5m`, `2h`, `7d`.
// Unlike Go durations it supports a `d` (day) unit and a single unit suffix.
type Timespan time.Duration

func (t Timespan) Duration() time.Duration { return time.Duration(t) }

func (t *Timespan) UnmarshalYAML(node *yaml.Node) error {
	var raw string
	if err := node.Decode(&raw); err != nil {
		return fmt.Errorf("correlation timespan must be a string like '5m': %w", err)
	}
	d, err := ParseTimespan(raw)
	if err != nil {
		return err
	}
	*t = Timespan(d)
	return nil
}

// ParseTimespan parses a Sigma timespan (a number followed by a single unit of
// s, m, h or d) into a time.Duration.
func ParseTimespan(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid timespan %q", s)
	}
	unit := s[len(s)-1]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return 0, fmt.Errorf("invalid timespan %q: %w", s, err)
	}
	switch unit {
	case 's':
		return time.Duration(n) * time.Second, nil
	case 'm':
		return time.Duration(n) * time.Minute, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("invalid timespan unit %q in %q (expected s, m, h or d)", string(unit), s)
	}
}

func (c *Correlation) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("correlation must be a mapping")
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		switch key.Value {
		case "type":
			if err := value.Decode(&c.Type); err != nil {
				return err
			}
		case "rules":
			rules, err := decodeStringOrList(value)
			if err != nil {
				return fmt.Errorf("correlation rules: %w", err)
			}
			c.Rules = rules
		case "group-by":
			groupBy, err := decodeStringOrList(value)
			if err != nil {
				return fmt.Errorf("correlation group-by: %w", err)
			}
			c.GroupBy = groupBy
		case "timespan":
			if err := value.Decode(&c.Timespan); err != nil {
				return err
			}
		case "aliases":
			if err := value.Decode(&c.Aliases); err != nil {
				return err
			}
		case "condition":
			cond := CorrelationCondition{}
			if err := cond.unmarshal(value); err != nil {
				return err
			}
			c.Condition = &cond
		}
	}
	return nil
}

func (c *CorrelationCondition) unmarshal(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("correlation condition must be a mapping like {gte: 10}")
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		switch key.Value {
		case "field":
			if err := value.Decode(&c.Field); err != nil {
				return err
			}
		case "gt", "gte", "lt", "lte", "eq", "neq":
			if err := value.Decode(&c.Count); err != nil {
				return err
			}
			c.Op = key.Value
		default:
			return fmt.Errorf("unknown correlation condition key %q", key.Value)
		}
	}
	if c.Op == "" {
		return fmt.Errorf("correlation condition must specify one of gt/gte/lt/lte/eq/neq")
	}
	return nil
}

// decodeStringOrList accepts either a single scalar or a sequence of scalars and
// returns them as a slice (Sigma allows both forms for `rules` and `group-by`).
func decodeStringOrList(node *yaml.Node) ([]string, error) {
	switch node.Kind {
	case yaml.ScalarNode:
		var s string
		if err := node.Decode(&s); err != nil {
			return nil, err
		}
		return []string{s}, nil
	case yaml.SequenceNode:
		var list []string
		if err := node.Decode(&list); err != nil {
			return nil, err
		}
		return list, nil
	default:
		return nil, fmt.Errorf("expected a string or list of strings")
	}
}
