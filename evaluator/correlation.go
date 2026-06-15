package evaluator

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/doracpphp/sigma-go"
)

// CorrelationEvaluator evaluates a Sigma correlation rule: a meta-rule that
// aggregates the matches of one or more referenced rules over a sliding time
// window (event_count, value_count, temporal, temporal_ordered).
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
	case sigma.CorrelationEventCount, sigma.CorrelationValueCount,
		sigma.CorrelationTemporal, sigma.CorrelationTemporalOrdered:
	default:
		return nil, fmt.Errorf("unsupported correlation type %q", correlation.Type)
	}
	if (correlation.Type == sigma.CorrelationEventCount || correlation.Type == sigma.CorrelationValueCount) && correlation.Condition == nil {
		return nil, fmt.Errorf("%s correlation requires a condition", correlation.Type)
	}
	if correlation.Type == sigma.CorrelationValueCount && correlation.Condition.Field == "" {
		return nil, fmt.Errorf("value_count correlation requires condition.field")
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

	value := ""
	if c.correlation.Condition != nil && c.correlation.Condition.Field != "" {
		value = fmt.Sprint(eventValue(event, c.correlation.Condition.Field))
	}

	fired := c.state.observe(now, key, observation{
		rules: matched,
		value: value,
	}, c.correlation, len(c.referenced))

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
				for idx := range matched {
					if concrete, ok := aliasMap[c.referenced[idx].ref]; ok {
						actualField = concrete
						break
					}
				}
			}
			v = eventValue(event, actualField)
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
	rules map[int]bool
	value string
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
	at    time.Time
	rules map[int]bool
	value string
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
	g.events = append(g.events, corrEvent{at: now, rules: obs.rules, value: obs.value})

	// Drop events that have aged out of the sliding window.
	cutoff := now.Add(-correlation.Timespan.Duration())
	kept := g.events[:0]
	for _, e := range g.events {
		if !e.at.Before(cutoff) {
			kept = append(kept, e)
		}
	}
	g.events = kept

	switch correlation.Type {
	case sigma.CorrelationEventCount:
		return compareCount(len(g.events), correlation.Condition)

	case sigma.CorrelationValueCount:
		distinct := map[string]struct{}{}
		for _, e := range g.events {
			distinct[e.value] = struct{}{}
		}
		return compareCount(len(distinct), correlation.Condition)

	case sigma.CorrelationTemporal:
		seen := map[int]bool{}
		for _, e := range g.events {
			for idx := range e.rules {
				seen[idx] = true
			}
		}
		return len(seen) == numRules

	case sigma.CorrelationTemporalOrdered:
		// Greedily walk the events in arrival (time) order, advancing through the
		// required rule sequence as each next-needed rule is matched.
		need := 0
		for _, e := range g.events {
			if e.rules[need] {
				need++
				if need == numRules {
					return true
				}
			}
		}
		return false
	}
	return false
}

func compareCount(count int, cond *sigma.CorrelationCondition) bool {
	if cond == nil {
		return false
	}
	switch cond.Op {
	case "gt":
		return count > cond.Count
	case "gte":
		return count >= cond.Count
	case "lt":
		return count < cond.Count
	case "lte":
		return count <= cond.Count
	case "eq":
		return count == cond.Count
	case "neq":
		return count != cond.Count
	default:
		return false
	}
}
