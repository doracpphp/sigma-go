package evaluator

import (
	"context"
	"testing"
	"time"

	"github.com/doracpphp/sigma-go"
)

func parse(t *testing.T, y string) sigma.Rule {
	t.Helper()
	r, err := sigma.ParseRule([]byte(y))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return r
}

func buildCorrelation(t *testing.T, corr string, referenced ...string) *CorrelationEvaluator {
	t.Helper()
	var refs []sigma.Rule
	for _, r := range referenced {
		refs = append(refs, parse(t, r))
	}
	e, err := ForCorrelation(parse(t, corr), refs)
	if err != nil {
		t.Fatalf("ForCorrelation: %v", err)
	}
	return e
}

const failedLogonRule = `
title: Failed logon
name: failed_logon
logsource:
  product: windows
detection:
  s:
    EventID: 4625
  condition: s
`

func TestCorrelationEventCount(t *testing.T) {
	c := buildCorrelation(t, `
title: Brute force
name: brute_force
correlation:
  type: event_count
  rules:
    - failed_logon
  group-by:
    - User
  timespan: 5m
  condition:
    gte: 3
`, failedLogonRule)

	ctx := context.Background()
	base := time.Now()
	evt := func(user string) map[string]interface{} {
		return map[string]interface{}{"EventID": 4625, "User": user}
	}

	// Two failures for alice: not yet.
	for i := 0; i < 2; i++ {
		res, err := c.matches(ctx, evt("alice"), base.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if res.Match {
			t.Fatalf("should not fire after %d failures", i+1)
		}
	}
	// Third failure fires.
	res, err := c.matches(ctx, evt("alice"), base.Add(3*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Match {
		t.Fatal("expected event_count >= 3 to fire on third failure")
	}
	if res.GroupValues["User"] != "alice" {
		t.Fatalf("unexpected group values %v", res.GroupValues)
	}

	// A different user is tracked independently.
	res, _ = c.matches(ctx, evt("bob"), base.Add(4*time.Second))
	if res.Match {
		t.Fatal("bob has only one failure, should not fire")
	}

	// An event unrelated to the referenced rule is ignored.
	res, _ = c.matches(ctx, map[string]interface{}{"EventID": 4624, "User": "alice"}, base.Add(5*time.Second))
	if res.Match || res.GroupValues != nil {
		t.Fatal("non-matching event should be ignored")
	}
}

func TestCorrelationEventCountWindowExpiry(t *testing.T) {
	c := buildCorrelation(t, `
title: Brute force
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [User]
  timespan: 5m
  condition:
    gte: 3
`, failedLogonRule)
	ctx := context.Background()
	base := time.Now()
	evt := map[string]interface{}{"EventID": 4625, "User": "alice"}

	// Two failures, then a third only after the first has aged out -> never 3 in window.
	c.matches(ctx, evt, base)
	c.matches(ctx, evt, base.Add(1*time.Minute))
	res, _ := c.matches(ctx, evt, base.Add(6*time.Minute)) // first (t=0) expired
	if res.Match {
		t.Fatal("events outside the 5m window must not accumulate")
	}
}

func TestCorrelationValueCount(t *testing.T) {
	c := buildCorrelation(t, `
title: Password spray
correlation:
  type: value_count
  rules: [failed_logon]
  group-by: [SourceIp]
  timespan: 10m
  condition:
    gte: 3
    field: User
`, failedLogonRule)
	ctx := context.Background()
	base := time.Now()
	evt := func(ip, user string) map[string]interface{} {
		return map[string]interface{}{"EventID": 4625, "SourceIp": ip, "User": user}
	}

	// Same user repeated from one IP: only 1 distinct user.
	for i := 0; i < 5; i++ {
		res, _ := c.matches(ctx, evt("10.0.0.1", "alice"), base.Add(time.Duration(i)*time.Second))
		if res.Match {
			t.Fatal("repeated single user should not be a spray")
		}
	}
	// Three distinct users from one IP fires.
	c.matches(ctx, evt("10.0.0.2", "u1"), base)
	c.matches(ctx, evt("10.0.0.2", "u2"), base.Add(time.Second))
	res, _ := c.matches(ctx, evt("10.0.0.2", "u3"), base.Add(2*time.Second))
	if !res.Match {
		t.Fatal("expected 3 distinct users from one IP to fire value_count")
	}
}

const ruleA = `
title: Rule A
name: rule_a
detection:
  s:
    EventID: 1
  condition: s
`

const ruleB = `
title: Rule B
name: rule_b
detection:
  s:
    EventID: 2
  condition: s
`

func TestCorrelationTemporal(t *testing.T) {
	c := buildCorrelation(t, `
title: A and B together
correlation:
  type: temporal
  rules:
    - rule_a
    - rule_b
  group-by: [Host]
  timespan: 5m
`, ruleA, ruleB)
	ctx := context.Background()
	base := time.Now()

	// Only A: not yet.
	res, _ := c.matches(ctx, map[string]interface{}{"EventID": 1, "Host": "h1"}, base)
	if res.Match {
		t.Fatal("only rule A matched, temporal should not fire")
	}
	// Then B on same host (order doesn't matter): fires.
	res, _ = c.matches(ctx, map[string]interface{}{"EventID": 2, "Host": "h1"}, base.Add(time.Second))
	if !res.Match {
		t.Fatal("A and B within window should fire temporal")
	}
	// B on a different host alone doesn't fire.
	res, _ = c.matches(ctx, map[string]interface{}{"EventID": 2, "Host": "h2"}, base.Add(2*time.Second))
	if res.Match {
		t.Fatal("only B matched for h2, should not fire")
	}
}

func TestCorrelationTemporalOrdered(t *testing.T) {
	corr := `
title: A then B
correlation:
  type: temporal_ordered
  rules:
    - rule_a
    - rule_b
  group-by: [Host]
  timespan: 5m
`
	ctx := context.Background()

	// Correct order A then B -> fires.
	c := buildCorrelation(t, corr, ruleA, ruleB)
	base := time.Now()
	c.matches(ctx, map[string]interface{}{"EventID": 1, "Host": "h1"}, base)
	res, _ := c.matches(ctx, map[string]interface{}{"EventID": 2, "Host": "h1"}, base.Add(time.Second))
	if !res.Match {
		t.Fatal("A then B should fire temporal_ordered")
	}

	// Wrong order B then A -> does not fire.
	c2 := buildCorrelation(t, corr, ruleA, ruleB)
	c2.matches(ctx, map[string]interface{}{"EventID": 2, "Host": "h9"}, base)
	res, _ = c2.matches(ctx, map[string]interface{}{"EventID": 1, "Host": "h9"}, base.Add(time.Second))
	if res.Match {
		t.Fatal("B then A is out of order, temporal_ordered should not fire")
	}
}

func TestForCorrelationErrors(t *testing.T) {
	// Missing referenced rule.
	_, err := ForCorrelation(parse(t, `
title: x
correlation:
  type: event_count
  rules: [does_not_exist]
  timespan: 5m
  condition: {gte: 1}
`), nil)
	if err == nil {
		t.Fatal("expected error for unknown referenced rule")
	}

	// Not a correlation rule.
	_, err = ForCorrelation(parse(t, failedLogonRule), nil)
	if err == nil {
		t.Fatal("expected error when rule has no correlation section")
	}
}

const successfulLogonRule = `
title: Successful logon
name: successful_logon
detection:
  s:
    EventID: 4624
  condition: s
`

// A chained correlation: an inner event_count correlation (a burst of failed
// logons) feeds an outer temporal_ordered correlation (the burst followed by a
// successful logon). This is the Sigma "Failed Logins Followed by Successful
// Login" example.
func TestCorrelationChained(t *testing.T) {
	// Inner: >= 3 failed logons for a User within the window.
	burst := `
title: Failed logon burst
name: failed_logon_burst
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [User]
  timespan: 5m
  condition: {gte: 3}
`
	// Outer: the burst, then a successful logon for the same User.
	chained := `
title: Burst then success
name: burst_then_success
correlation:
  type: temporal_ordered
  rules:
    - failed_logon_burst
    - successful_logon
  group-by: [User]
  timespan: 5m
`
	ctx := context.Background()

	build := func() *CorrelationEvaluator {
		return buildCorrelation(t, chained, failedLogonRule, successfulLogonRule, burst)
	}
	failed := func(user string) map[string]interface{} {
		return map[string]interface{}{"EventID": 4625, "User": user}
	}
	success := func(user string) map[string]interface{} {
		return map[string]interface{}{"EventID": 4624, "User": user}
	}

	// Correct sequence: three failures (the third fires the inner burst), then a
	// successful logon -> the chained correlation fires.
	c := build()
	base := time.Now()
	for i := 0; i < 3; i++ {
		if res, err := c.matches(ctx, failed("alice"), base.Add(time.Duration(i)*time.Second)); err != nil {
			t.Fatal(err)
		} else if res.Match {
			t.Fatalf("chained correlation should not fire on failure %d", i+1)
		}
	}
	res, err := c.matches(ctx, success("alice"), base.Add(4*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Match {
		t.Fatal("burst followed by successful logon should fire the chained correlation")
	}
	if res.GroupValues["User"] != "alice" {
		t.Fatalf("unexpected group values %v", res.GroupValues)
	}

	// A successful logon before the burst completes must not fire (ordering), and a
	// different user is tracked independently.
	c2 := build()
	if res, _ := c2.matches(ctx, success("bob"), base); res.Match {
		t.Fatal("successful logon before any burst should not fire")
	}
	for i := 0; i < 3; i++ {
		c2.matches(ctx, failed("bob"), base.Add(time.Duration(i+1)*time.Second))
	}
	// Only two failures for carol: the inner burst never fires, so neither does the chain.
	c3 := build()
	c3.matches(ctx, failed("carol"), base)
	c3.matches(ctx, failed("carol"), base.Add(time.Second))
	if res, _ := c3.matches(ctx, success("carol"), base.Add(2*time.Second)); res.Match {
		t.Fatal("only two failures: inner burst should not fire, so the chain should not fire")
	}
}

// A correlation that references itself (directly or transitively) must be rejected
// at build time rather than recursing forever.
func TestCorrelationCycleDetected(t *testing.T) {
	selfRef := `
title: Self referencing
name: loop
correlation:
  type: temporal
  rules: [loop]
  group-by: [User]
  timespan: 5m
`
	_, err := ForCorrelation(parse(t, selfRef), []sigma.Rule{parse(t, selfRef)})
	if err == nil {
		t.Fatal("expected a cycle error for a self-referencing correlation")
	}
}
