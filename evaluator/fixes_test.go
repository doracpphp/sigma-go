package evaluator

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/doracpphp/sigma-go"
)

// Escaped wildcards (`\*`, `\?`, `\\`) in contains/startswith/endswith values
// must match their literal characters, not the raw backslash text.
func TestEscapedWildcardAffixMatching(t *testing.T) {
	rule := parse(t, `
title: escaped wildcards
detection:
  contains_star:
    CommandLine|contains: 'foo\*bar'
  contains_backslash:
    Path|contains: 'a\\b'
  starts:
    CommandLine|startswith: 'foo\*'
  condition: contains_star or contains_backslash or starts
`)
	e := ForRule(rule)
	ctx := context.Background()

	cases := []struct {
		event map[string]interface{}
		match bool
	}{
		{map[string]interface{}{"CommandLine": "a foo*bar b"}, true},
		{map[string]interface{}{"CommandLine": "a fooXbar b"}, false},
		{map[string]interface{}{"Path": `x a\b y`}, true},
		{map[string]interface{}{"CommandLine": "foo* the rest"}, true},
	}
	for i, tc := range cases {
		res, err := e.Matches(ctx, tc.event)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if res.Match != tc.match {
			t.Errorf("case %d: got match=%v, want %v (event %v)", i, res.Match, tc.match, tc.event)
		}
	}
}

// The same escaped-wildcard values must also match when evaluated through a
// bundle (the Aho-Corasick trie must hold the unescaped literal).
func TestEscapedWildcardContainsBundle(t *testing.T) {
	rule := parse(t, `
title: escaped wildcards bundle
detection:
  sel:
    CommandLine|contains: 'foo\*bar'
  condition: sel
`)
	bundle := ForRules([]sigma.Rule{rule})
	results, err := bundle.Matches(context.Background(), map[string]interface{}{"CommandLine": "a foo*bar b"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].Match {
		t.Fatal("bundle should match the literal foo*bar substring")
	}
}

// fieldref compares the two field values literally: a `*` in the referenced
// event field must not act as a wildcard.
func TestFieldRefIsLiteral(t *testing.T) {
	rule := parse(t, `
title: fieldref literal
detection:
  sel:
    TargetName|fieldref: SourceName
  condition: sel
`)
	e := ForRule(rule)
	ctx := context.Background()

	// A wildcard in the referenced value must not match everything.
	res, err := e.Matches(ctx, map[string]interface{}{"TargetName": "completely-different", "SourceName": "*"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Match {
		t.Fatal("fieldref must not interpret event values as wildcards")
	}

	// Identical values (including wildcard characters and backslashes) match.
	for _, v := range []string{"*", "x*y", `C:\Windows\Temp`, "plain"} {
		res, err := e.Matches(ctx, map[string]interface{}{"TargetName": v, "SourceName": v})
		if err != nil {
			t.Fatal(err)
		}
		if !res.Match {
			t.Errorf("fieldref should match identical values %q", v)
		}
	}
}

// A regex with no "necessary substrings" (e.g. `.+`) used to nil-panic inside a
// bundle because the field had no Aho-Corasick trie.
func TestBundleRegexWithoutNecessaryStringsDoesNotPanic(t *testing.T) {
	rule := parse(t, `
title: regex without needles
detection:
  sel:
    SomeField|re: '.+'
  condition: sel
`)
	bundle := ForRules([]sigma.Rule{rule})
	results, err := bundle.Matches(context.Background(), map[string]interface{}{"SomeField": "anything"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].Match {
		t.Fatal("re: '.+' should match a non-empty field")
	}
	results, err = bundle.Matches(context.Background(), map[string]interface{}{"OtherField": "x"})
	if err != nil {
		t.Fatal(err)
	}
	if results[0].Match {
		t.Fatal("re: '.+' should not match an absent field")
	}
}

// `contains: null` used to nil-panic inside a bundle: the nil value is skipped
// at build time but becomes the "null" sentinel needle at match time.
func TestBundleContainsNullDoesNotPanic(t *testing.T) {
	rule := parse(t, `
title: contains null
detection:
  sel:
    SomeField|contains: null
  condition: sel
`)
	bundle := ForRules([]sigma.Rule{rule})
	if _, err := bundle.Matches(context.Background(), map[string]interface{}{"SomeField": "anything"}); err != nil {
		t.Fatal(err)
	}
}

// A case-insensitive `contains` and a case-sensitive `re` on the same field used
// to poison each other's trie-scan cache (the cache key ignored case
// sensitivity), so whichever rule ran second silently didn't match.
func TestBundleCaseSensitivityCacheIsolation(t *testing.T) {
	containsRule := parse(t, `
title: ci contains
detection:
  sel:
    CommandLine|contains: 'MIMIKATZ'
  condition: sel
`)
	reRule := parse(t, `
title: cs regex
detection:
  sel:
    CommandLine|re: 'MimiKatz'
  condition: sel
`)
	for _, rules := range [][]sigma.Rule{
		{containsRule, reRule},
		{reRule, containsRule}, // both orders
	} {
		bundle := ForRules(rules)
		results, err := bundle.Matches(context.Background(), map[string]interface{}{"CommandLine": "run MimiKatz now"})
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range results {
			if !r.Match {
				t.Errorf("rule %q should match regardless of evaluation order", r.Rule.Title)
			}
		}
	}
}

// Placeholder values only exist at match time, so they can't be in the bundle's
// trie; they must fall back to the standard contains comparator.
func TestBundlePlaceholderContains(t *testing.T) {
	rule := parse(t, `
title: placeholder contains
detection:
  sel:
    User|contains: '%users%'
  condition: sel
`)
	bundle := ForRules([]sigma.Rule{rule}, WithPlaceholderExpander(func(ctx context.Context, name string) ([]string, error) {
		return []string{"alice"}, nil
	}))
	results, err := bundle.Matches(context.Background(), map[string]interface{}{"User": "malice"})
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 || !results[0].Match {
		t.Fatal("placeholder-derived needle should match via the fallback comparator")
	}
}

// avg()/sum() without an implementation must return an error, not nil-panic.
func TestAvgSumWithoutImplementationErrors(t *testing.T) {
	for _, cond := range []string{"s | avg(Size) > 5", "s | sum(Size) > 5"} {
		rule := parse(t, `
title: agg
detection:
  s:
    EventID: 1
  condition: `+cond+`
`)
		e := ForRule(rule)
		_, err := e.Matches(context.Background(), map[string]interface{}{"EventID": 1, "Size": 10})
		if err == nil || !strings.Contains(err.Error(), "implementation") {
			t.Errorf("%s: expected descriptive error, got %v", cond, err)
		}
	}
}

// Two different rules with identical aggregation shapes must not share state.
func TestAggregationStateIsPerRule(t *testing.T) {
	ruleYAML := func(title string) string {
		return `
title: ` + title + `
detection:
  s:
    EventID: 4625
  timeframe: 5m
  condition: s | count() by User > 2
`
	}
	a := parse(t, ruleYAML("rule a"))
	b := parse(t, ruleYAML("rule b"))
	gv := func(rule sigma.Rule, user string) GroupedByValues {
		return ForRule(rule).groupedBy(0, map[string]interface{}{"User": user}, []string{"User"})
	}
	keyA1, keyA2, keyB := gv(a, "alice").Key(), gv(a, "alice").Key(), gv(b, "alice").Key()
	if keyA1 == keyB {
		t.Fatal("different rules must produce different aggregation bucket keys")
	}
	if keyA1 != keyA2 {
		t.Fatal("the same rule must produce a stable bucket key")
	}
}

// A correlation condition with two operators is an AND (a range), not
// last-one-wins.
func TestCorrelationConditionRange(t *testing.T) {
	c := buildCorrelation(t, `
title: between 3 and 4
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [User]
  timespan: 5m
  condition:
    gte: 3
    lte: 4
`, failedLogonRule)
	ctx := context.Background()
	base := time.Now()
	evt := map[string]interface{}{"EventID": 4625, "User": "alice"}

	for i := 0; i < 2; i++ {
		res, _ := c.matches(ctx, evt, base.Add(time.Duration(i)*time.Second))
		if res.Match {
			t.Fatalf("count=%d is below the gte bound, must not fire", i+1)
		}
	}
	res, _ := c.matches(ctx, evt, base.Add(2*time.Second))
	if !res.Match {
		t.Fatal("count=3 is inside [3,4], should fire")
	}
}

// A correlation without a timespan must be rejected at build time instead of
// silently never firing.
func TestCorrelationRequiresTimespan(t *testing.T) {
	_, err := ForCorrelation(parse(t, `
title: no timespan
correlation:
  type: event_count
  rules: [failed_logon]
  condition: {gte: 2}
`), []sigma.Rule{parse(t, failedLogonRule)})
	if err == nil || !strings.Contains(err.Error(), "timespan") {
		t.Fatalf("expected timespan error, got %v", err)
	}
}

// Once a correlation fires, its bucket resets: one incident produces one alert,
// not one alert per subsequent event.
func TestCorrelationFiresOncePerIncident(t *testing.T) {
	c := buildCorrelation(t, `
title: Brute force
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [User]
  timespan: 5m
  condition: {gte: 3}
`, failedLogonRule)
	ctx := context.Background()
	base := time.Now()
	evt := map[string]interface{}{"EventID": 4625, "User": "alice"}

	fires := 0
	for i := 0; i < 6; i++ {
		res, err := c.matches(ctx, evt, base.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if res.Match {
			fires++
		}
	}
	// 6 events with threshold 3: fires on the 3rd and (after the reset) the 6th.
	if fires != 2 {
		t.Fatalf("expected 2 firings for 6 events with gte:3, got %d", fires)
	}
}

// value_count must not count an absent condition field as a distinct value.
func TestValueCountIgnoresAbsentField(t *testing.T) {
	c := buildCorrelation(t, `
title: Password spray
correlation:
  type: value_count
  rules: [failed_logon]
  group-by: [SourceIp]
  timespan: 10m
  condition:
    gte: 2
    field: User
`, failedLogonRule)
	ctx := context.Background()
	base := time.Now()

	c.matches(ctx, map[string]interface{}{"EventID": 4625, "SourceIp": "10.0.0.1", "User": "alice"}, base)
	// Second event has no User field at all: only one real distinct user so far.
	res, _ := c.matches(ctx, map[string]interface{}{"EventID": 4625, "SourceIp": "10.0.0.1"}, base.Add(time.Second))
	if res.Match {
		t.Fatal("an event without the condition field must not count as a distinct value")
	}
	res, _ = c.matches(ctx, map[string]interface{}{"EventID": 4625, "SourceIp": "10.0.0.1", "User": "bob"}, base.Add(2*time.Second))
	if !res.Match {
		t.Fatal("two real distinct users should fire")
	}
}

// temporal_ordered orders by event time, not arrival order.
func TestTemporalOrderedUsesEventTime(t *testing.T) {
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
	base := time.Now()

	// rule_b's event is chronologically FIRST (t+1s) but arrives second;
	// rule_a's is chronologically second (t+2s) but arrives first.
	// True order is A(t+2) after B(t+1)? No: B at t+1 precedes A at t+2, so "A then B" must NOT fire.
	c := buildCorrelation(t, corr, ruleA, ruleB)
	c.matches(ctx, map[string]interface{}{"EventID": 1, "Host": "h1"}, base.Add(2*time.Second)) // A at t+2
	res, _ := c.matches(ctx, map[string]interface{}{"EventID": 2, "Host": "h1"}, base.Add(time.Second)) // B at t+1 (late arrival)
	if res.Match {
		t.Fatal("chronologically B precedes A, so 'A then B' must not fire")
	}

	// The reverse: A arrives late but is chronologically first -> fires.
	c2 := buildCorrelation(t, corr, ruleA, ruleB)
	c2.matches(ctx, map[string]interface{}{"EventID": 2, "Host": "h2"}, base.Add(2*time.Second)) // B at t+2
	res, _ = c2.matches(ctx, map[string]interface{}{"EventID": 1, "Host": "h2"}, base.Add(time.Second)) // A at t+1 (late arrival)
	if !res.Match {
		t.Fatal("chronologically A precedes B, so 'A then B' should fire despite arrival order")
	}
}

// The near aggregation must window by the event time from the context, not by
// wall-clock arrival time, so historical replays don't collapse into "now".
func TestNearUsesEventTime(t *testing.T) {
	rule := parse(t, `
title: near with event time
detection:
  selection:
    EventID: 1
  other:
    EventID: 2
  timeframe: 5m
  condition: selection | near other
`)
	e := ForRule(rule)

	base := time.Now().Add(-24 * time.Hour)
	// "other" matched at base.
	ctx1 := WithEventTime(context.Background(), base)
	if _, err := e.Matches(ctx1, map[string]interface{}{"EventID": 2}); err != nil {
		t.Fatal(err)
	}
	// selection two hours later: far outside the 5m window, must not fire even
	// though both events were replayed within milliseconds of wall-clock time.
	ctx2 := WithEventTime(context.Background(), base.Add(2*time.Hour))
	res, err := e.Matches(ctx2, map[string]interface{}{"EventID": 1})
	if err != nil {
		t.Fatal(err)
	}
	if res.Match {
		t.Fatal("events 2h apart in event time must not satisfy a 5m near window")
	}

	// And within the window it does fire.
	e2 := ForRule(rule)
	e2.Matches(WithEventTime(context.Background(), base), map[string]interface{}{"EventID": 2})
	res, _ = e2.Matches(WithEventTime(context.Background(), base.Add(time.Minute)), map[string]interface{}{"EventID": 1})
	if !res.Match {
		t.Fatal("events 1m apart in event time should satisfy a 5m near window")
	}
}
