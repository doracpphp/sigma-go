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

	// Generate mirrors the spec's `generate` flag (emit the matches of the
	// referenced rules as well). It is parsed for round-trip fidelity; the
	// evaluator doesn't act on it.
	Generate bool `yaml:",omitempty" json:",omitempty"`
}

// CorrelationCondition is the threshold comparison for event_count / value_count
// correlation rules, e.g. `{gte: 10}` or, for value_count, `{gte: 100, field: User}`.
// Multiple operators (e.g. `{gte: 10, lte: 20}`) are linked with logical AND, per
// the Sigma correlation specification.
type CorrelationCondition struct {
	// Op and Count mirror the first term in Terms, for convenience and backwards
	// compatibility. Op is one of gt, gte, lt, lte, eq, neq.
	Op    string
	Count int
	// Terms holds every operator in the condition; all of them must hold (AND).
	Terms []CorrelationConditionTerm
	// Field is the field whose distinct values are counted (value_count only).
	Field string
}

// CorrelationConditionTerm is a single operator/threshold pair of a correlation
// condition.
type CorrelationConditionTerm struct {
	Op    string
	Count int
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

// MarshalYAML emits the timespan in Sigma syntax (`30s`, `5m`, `2h`, `7d`) so a
// marshalled correlation rule can be re-parsed (the default encoding would be
// raw nanoseconds, which UnmarshalYAML rejects).
func (t Timespan) MarshalYAML() (interface{}, error) {
	d := t.Duration()
	day := 24 * time.Hour
	switch {
	case d >= day && d%day == 0:
		return fmt.Sprintf("%dd", d/day), nil
	case d >= time.Hour && d%time.Hour == 0:
		return fmt.Sprintf("%dh", d/time.Hour), nil
	case d >= time.Minute && d%time.Minute == 0:
		return fmt.Sprintf("%dm", d/time.Minute), nil
	default:
		return fmt.Sprintf("%ds", d/time.Second), nil
	}
}

// ParseTimespan parses a Sigma timespan (a positive number followed by a single
// unit of s, m, h or d) into a time.Duration.
func ParseTimespan(s string) (time.Duration, error) {
	if len(s) < 2 {
		return 0, fmt.Errorf("invalid timespan %q", s)
	}
	unit := s[len(s)-1]
	n, err := strconv.Atoi(s[:len(s)-1])
	if err != nil {
		return 0, fmt.Errorf("invalid timespan %q: %w", s, err)
	}
	if n <= 0 {
		return 0, fmt.Errorf("invalid timespan %q: must be positive", s)
	}
	var mult time.Duration
	switch unit {
	case 's':
		mult = time.Second
	case 'm':
		mult = time.Minute
	case 'h':
		mult = time.Hour
	case 'd':
		mult = 24 * time.Hour
	default:
		return 0, fmt.Errorf("invalid timespan unit %q in %q (expected s, m, h or d)", string(unit), s)
	}
	if time.Duration(n) > time.Duration(1<<62)/mult {
		return 0, fmt.Errorf("invalid timespan %q: too large", s)
	}
	return time.Duration(n) * mult, nil
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
		case "generate":
			if err := value.Decode(&c.Generate); err != nil {
				return err
			}
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
			// Multiple operators are allowed and linked with logical AND
			// (e.g. {gte: 10, lte: 20} means "between 10 and 20").
			var count int
			if err := value.Decode(&count); err != nil {
				return err
			}
			c.Terms = append(c.Terms, CorrelationConditionTerm{Op: key.Value, Count: count})
		default:
			return fmt.Errorf("unknown correlation condition key %q", key.Value)
		}
	}
	if len(c.Terms) == 0 {
		return fmt.Errorf("correlation condition must specify one of gt/gte/lt/lte/eq/neq")
	}
	c.Op = c.Terms[0].Op
	c.Count = c.Terms[0].Count
	return nil
}

// MarshalYAML emits the condition in the mapping form UnmarshalYAML accepts
// ({gte: 10, field: User}), not the raw struct fields.
func (c CorrelationCondition) MarshalYAML() (interface{}, error) {
	node := &yaml.Node{Kind: yaml.MappingNode}
	appendPair := func(key string, value interface{}) error {
		k := &yaml.Node{}
		if err := k.Encode(key); err != nil {
			return err
		}
		v := &yaml.Node{}
		if err := v.Encode(value); err != nil {
			return err
		}
		node.Content = append(node.Content, k, v)
		return nil
	}
	terms := c.Terms
	if len(terms) == 0 && c.Op != "" {
		terms = []CorrelationConditionTerm{{Op: c.Op, Count: c.Count}}
	}
	for _, term := range terms {
		if err := appendPair(term.Op, term.Count); err != nil {
			return nil, err
		}
	}
	if c.Field != "" {
		if err := appendPair("field", c.Field); err != nil {
			return nil, err
		}
	}
	return node, nil
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
