package evaluator

import (
	"context"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/doracpphp/sigma-go"
)

// CorrelationEvaluator evaluates a Sigma correlation rule: a meta-rule that
// aggregates the matches of one or more referenced rules over a sliding time
// window (event_count, value_count, temporal, temporal_ordered, value_sum,
// value_avg).
//
// It is stateful: feed it the same stream of events you feed your normal rule
// evaluators and it raises a match when the correlation condition is met. State
// is kept in-memory and partitioned by the rule's group-by values.
type CorrelationEvaluator struct {
	Rule        sigma.Rule
	correlation sigma.Correlation
	referenced  []referencedRule
	state       *correlationState
}

// referencedRule is one entry of a correlation's `rules` list. A reference is
// either a detection rule (eval) or, for chained correlations, another correlation
// rule (corr). Exactly one of the two is set.
type referencedRule struct {
	ref  string                // the name or id used to reference the rule
	eval *RuleEvaluator        // set when the reference is a detection rule
	corr *CorrelationEvaluator // set when the reference is another correlation (chaining)
}

// CorrelationResult is the outcome of evaluating a single event against a
// correlation rule.
type CorrelationResult struct {
	// Match is true if this event caused the correlation condition to be met.
	Match bool
	// GroupValues are the group-by field values of the bucket that fired (nil if
	// no referenced rule matched this event).
	GroupValues map[string]interface{}
}

// ForCorrelation builds an evaluator for a correlation rule. referencedRules must
// contain every rule named in the correlation's `rules` list (looked up by Name
// or ID); options are passed through to each referenced rule's evaluator.
//
// A correlation may reference other correlation rules ("chained correlations", per
// the Sigma spec): such references are built recursively into nested correlation
// evaluators, and a child's firing is fed to the parent as a matching event.
func ForCorrelation(rule sigma.Rule, referencedRules []sigma.Rule, options ...Option) (*CorrelationEvaluator, error) {
	return forCorrelation(rule, referencedRules, map[string]bool{}, options...)
}

// forCorrelation is the recursive implementation. visiting holds the name/id of
// every correlation currently being built on the chain above this one, so a cycle
// (a correlation that references itself directly or transitively) is reported
// rather than recursing forever.
func forCorrelation(rule sigma.Rule, referencedRules []sigma.Rule, visiting map[string]bool, options ...Option) (*CorrelationEvaluator, error) {
	if rule.Correlation == nil {
		return nil, fmt.Errorf("rule %q is not a correlation rule", rule.Title)
	}
	correlation := *rule.Correlation
	switch correlation.Type {
	case sigma.CorrelationTemporal, sigma.CorrelationTemporalOrdered:
	case sigma.CorrelationEventCount:
		if correlation.Condition == nil {
			return nil, fmt.Errorf("%s correlation requires a condition", correlation.Type)
		}
	case sigma.CorrelationValueCount, sigma.CorrelationValueSum, sigma.CorrelationValueAvg:
		if correlation.Condition == nil {
			return nil, fmt.Errorf("%s correlation requires a condition", correlation.Type)
		}
		if correlation.Condition.Field == "" {
			return nil, fmt.Errorf("%s correlation requires condition.field", correlation.Type)
		}
	default:
		return nil, fmt.Errorf("unsupported correlation type %q", correlation.Type)
	}
	if correlation.Timespan.Duration() <= 0 {
		// The spec makes timespan mandatory; without one the sliding window is
		// empty and the correlation would silently never fire.
		return nil, fmt.Errorf("correlation requires a positive timespan (e.g. \"5m\")")
	}

	lookup := map[string]sigma.Rule{}
	for _, r := range referencedRules {
		if r.Name != "" {
			lookup[r.Name] = r
		}
		if r.ID != "" {
			lookup[r.ID] = r
		}
	}

	if len(correlation.Rules) == 0 {
		return nil, fmt.Errorf("correlation rule references no rules")
	}

	// Mark this correlation as on the current chain for cycle detection, and unmark
	// it when this branch finishes so sibling branches aren't falsely flagged.
	selfKeys := make([]string, 0, 2)
	if rule.Name != "" {
		selfKeys = append(selfKeys, rule.Name)
	}
	if rule.ID != "" {
		selfKeys = append(selfKeys, rule.ID)
	}
	for _, k := range selfKeys {
		visiting[k] = true
	}
	defer func() {
		for _, k := range selfKeys {
			delete(visiting, k)
		}
	}()

	e := &CorrelationEvaluator{
		Rule:        rule,
		correlation: correlation,
		state:       &correlationState{groups: map[string]*corrGroup{}},
	}
	for _, ref := range correlation.Rules {
		referenced, ok := lookup[ref]
		if !ok {
			return nil, fmt.Errorf("correlation references unknown rule %q", ref)
		}
		rr := referencedRule{ref: ref}
		if referenced.Correlation != nil {
			// Chained correlation: build the referenced correlation recursively.
			if visiting[ref] {
				return nil, fmt.Errorf("correlation cycle detected at rule %q", ref)
			}
			child, err := forCorrelation(referenced, referencedRules, visiting, options...)
			if err != nil {
				return nil, fmt.Errorf("building chained correlation %q: %w", ref, err)
			}
			rr.corr = child
		} else {
			rr.eval = ForRule(referenced, options...)
		}
		e.referenced = append(e.referenced, rr)
	}
	return e, nil
}

func (c *CorrelationEvaluator) Matches(ctx context.Context, event Event) (CorrelationResult, error) {
	// Window by the event's own timestamp when the caller supplied one (correct for
	// offline replay), otherwise by wall-clock arrival time.
	return c.matches(ctx, event, eventTimeOrNow(ctx))
}

func (c *CorrelationEvaluator) matches(ctx context.Context, event Event, now time.Time) (CorrelationResult, error) {
	// Determine which of the referenced rules match this event. Chained
	// correlations are fed every event (to keep their own window state current) and
	// count as a match for this event when they fire.
	matched := map[int]bool{}
	var childGroupValues map[string]interface{}
	for idx, ref := range c.referenced {
		if ref.corr != nil {
			res, err := ref.corr.matches(ctx, event, now)
			if err != nil {
				return CorrelationResult{}, fmt.Errorf("evaluating chained correlation %q: %w", ref.ref, err)
			}
			if res.Match {
				matched[idx] = true
				// Carry the child's group-by values up so the parent groups the
				// firing consistently even when it can't read them off the raw event.
				if childGroupValues == nil {
					childGroupValues = map[string]interface{}{}
				}
				for k, v := range res.GroupValues {
					childGroupValues[k] = v
				}
			}
			continue
		}
		res, err := ref.eval.Matches(ctx, event)
		if err != nil {
			return CorrelationResult{}, fmt.Errorf("evaluating referenced rule %q: %w", ref.ref, err)
		}
		if res.Match {
			matched[idx] = true
		}
	}
	if len(matched) == 0 {
		// This event is irrelevant to the correlation.
		return CorrelationResult{}, nil
	}

	key, groupValues := c.groupKey(event, matched, childGroupValues)

	obs := observation{rules: matched}
	if c.correlation.Condition != nil && c.correlation.Condition.Field != "" {
		// An absent field must not be counted as a distinct value (a password-spray
		// rule would otherwise count "<nil>" as an extra user).
		if field := c.correlation.Condition.Field; eventKeyExists(event, field) {
			raw := eventValue(event, field)
			obs.value = fmt.Sprint(raw)
			obs.hasValue = true
			// value_sum / value_avg only aggregate values that are numbers.
			obs.num, obs.hasNum = numericValue(raw)
		}
	}

	fired := c.state.observe(now, key, obs, c.correlation, len(c.referenced))

	return CorrelationResult{Match: fired, GroupValues: groupValues}, nil
}

// groupKey computes the bucket key and the group-by values for an event. Group-by
// fields that are aliases are resolved to the concrete field of whichever
// referenced rule matched the event. Values in overrides (supplied by a fired
// chained correlation) take precedence over the raw event, so a parent groups a
// child's firing the same way the child did even if the field isn't on the event.
func (c *CorrelationEvaluator) groupKey(event Event, matched map[int]bool, overrides map[string]interface{}) (string, map[string]interface{}) {
	values := make(map[string]interface{}, len(c.correlation.GroupBy))
	var b strings.Builder
	for _, field := range c.correlation.GroupBy {
		var v interface{}
		if ov, ok := overrides[field]; ok {
			v = ov
		} else {
			actualField := field
			if aliasMap, ok := c.correlation.Aliases[field]; ok {
				// Walk the referenced rules in declaration order so that an event
				// matching several of them always resolves the alias to the same
				// field (map iteration order would make bucketing nondeterministic).
				for idx := range c.referenced {
					if !matched[idx] {
						continue
					}
					if concrete, ok := aliasMap[c.referenced[idx].ref]; ok {
						actualField = concrete
						break
					}
				}
			}
			// Distinguish "field absent" from any real value, and do it the same
			// way for map[string]string and map[string]interface{} events so both
			// land in the same bucket.
			if eventKeyExists(event, actualField) {
				v = eventValue(event, actualField)
			}
		}
		values[field] = v
		b.WriteString(field)
		b.WriteByte('=')
		b.WriteString(fmt.Sprint(v))
		b.WriteByte(0)
	}
	return b.String(), values
}

type observation struct {
	rules    map[int]bool
	value    string
	hasValue bool
	num      float64
	hasNum   bool
}

// numericValue interprets an event field value as a number for value_sum and
// value_avg: numeric Go values directly, strings when they parse as a decimal
// float or an integer literal (including 0x hex, as Windows renders many fields).
func numericValue(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case int:
		return float64(n), true
	case int8:
		return float64(n), true
	case int16:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case uint:
		return float64(n), true
	case uint8:
		return float64(n), true
	case uint16:
		return float64(n), true
	case uint32:
		return float64(n), true
	case uint64:
		return float64(n), true
	case float32:
		return float64(n), true
	case float64:
		return n, true
	}
	s := strings.TrimSpace(fmt.Sprint(v))
	// NaN/Inf parse as floats but would poison every later sum and average.
	if f, err := strconv.ParseFloat(s, 64); err == nil && !math.IsNaN(f) && !math.IsInf(f, 0) {
		return f, true
	}
	if i, err := strconv.ParseInt(s, 0, 64); err == nil {
		return float64(i), true
	}
	if u, err := strconv.ParseUint(s, 0, 64); err == nil {
		return float64(u), true
	}
	return 0, false
}

type correlationState struct {
	mu     sync.Mutex
	groups map[string]*corrGroup
	ops    int
}

// sweepInterval is how many observations happen between eviction sweeps of
// groups whose events have all aged out of the window. Without eviction the
// per-group state grows without bound on high-cardinality group-by fields.
const sweepInterval = 4096

// sweepBatch bounds how many groups a single sweep examines so the pause while
// holding the lock stays bounded no matter how many groups exist (Go map
// iteration starts at a random position, so successive partial sweeps
// eventually visit every entry).
const sweepBatch = 4 * sweepInterval

func (s *correlationState) maybeSweep(now time.Time, timespan time.Duration) {
	s.ops++
	if s.ops%sweepInterval != 0 {
		return
	}
	cutoff := now.Add(-timespan)
	scanned := 0
	for key, g := range s.groups {
		scanned++
		if scanned > sweepBatch {
			break
		}
		if len(g.events) == 0 || g.events[len(g.events)-1].at.Before(cutoff) {
			delete(s.groups, key)
		}
	}
}

type corrGroup struct {
	events []corrEvent
}

type corrEvent struct {
	at       time.Time
	rules    map[int]bool
	value    string
	hasValue bool
	num      float64
	hasNum   bool
}

func (s *correlationState) observe(now time.Time, key string, obs observation, correlation sigma.Correlation, numRules int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.maybeSweep(now, correlation.Timespan.Duration())

	g, ok := s.groups[key]
	if !ok {
		g = &corrGroup{}
		s.groups[key] = g
	}

	// Insert in event-time order so temporal_ordered sees the true chronology even
	// when events arrive out of order (multi-source ingestion, replay), and so the
	// newest event is always last (the sweep relies on that). Events almost always
	// arrive in order, so this is an append in the common case.
	ev := corrEvent{at: now, rules: obs.rules, value: obs.value, hasValue: obs.hasValue, num: obs.num, hasNum: obs.hasNum}
	pos := len(g.events)
	for pos > 0 && g.events[pos-1].at.After(now) {
		pos--
	}
	g.events = append(g.events, corrEvent{})
	copy(g.events[pos+1:], g.events[pos:])
	g.events[pos] = ev

	// Drop events that have aged out of the sliding window (relative to the newest
	// event, which with sorted insertion is the last one).
	cutoff := g.events[len(g.events)-1].at.Add(-correlation.Timespan.Duration())
	kept := g.events[:0]
	for _, e := range g.events {
		if !e.at.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	g.events = kept

	fired := false
	switch correlation.Type {
	case sigma.CorrelationEventCount:
		fired = compareThreshold(float64(len(g.events)), correlation.Condition)

	case sigma.CorrelationValueCount:
		distinct := map[string]struct{}{}
		for _, e := range g.events {
			if e.hasValue {
				distinct[e.value] = struct{}{}
			}
		}
		fired = compareThreshold(float64(len(distinct)), correlation.Condition)

	case sigma.CorrelationValueSum, sigma.CorrelationValueAvg:
		sum, n := 0.0, 0
		for _, e := range g.events {
			if e.hasNum {
				sum += e.num
				n++
			}
		}
		if n == 0 {
			// No numeric value in the window yet: there is nothing to compare.
			break
		}
		if correlation.Type == sigma.CorrelationValueAvg {
			sum /= float64(n)
		}
		fired = compareThreshold(sum, correlation.Condition)

	case sigma.CorrelationTemporal:
		seen := map[int]bool{}
		for _, e := range g.events {
			for idx := range e.rules {
				seen[idx] = true
			}
		}
		fired = len(seen) == numRules

	case sigma.CorrelationTemporalOrdered:
		// Greedily walk the events in chronological order, advancing through the
		// required rule sequence as each next-needed rule is matched.
		need := 0
		for _, e := range g.events {
			if e.rules[need] {
				need++
				if need == numRules {
					fired = true
					break
				}
			}
		}
	}

	if fired {
		// Reset the bucket so one incident raises one alert: without this, every
		// further in-window event re-fires the correlation (an alert flood), and a
		// chained parent would count the same incident many times.
		delete(s.groups, key)
	}
	return fired
}

// compareThreshold reports whether value satisfies every term of the
// correlation condition (multiple terms are linked with logical AND per the
// spec).
func compareThreshold(value float64, cond *sigma.CorrelationCondition) bool {
	if cond == nil {
		return false
	}
	terms := cond.Terms
	if len(terms) == 0 {
		terms = []sigma.CorrelationConditionTerm{{Op: cond.Op, Count: cond.Count}}
	}
	for _, term := range terms {
		threshold := term.Value()
		ok := false
		switch term.Op {
		case "gt":
			ok = value > threshold
		case "gte":
			ok = value >= threshold
		case "lt":
			ok = value < threshold
		case "lte":
			ok = value <= threshold
		case "eq":
			ok = value == threshold
		case "neq":
			ok = value != threshold
		}
		if !ok {
			return false
		}
	}
	return true
}
