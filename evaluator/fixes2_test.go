package evaluator

import (
	"context"
	"testing"
	"time"

	"github.com/doracpphp/sigma-go"
)

// `1 of selection` / `all of selection` (an identifier without a wildcard) is
// valid Sigma; evaluating it used to panic with "unhandled node type".
func TestOneOfAllOfPlainIdentifier(t *testing.T) {
	rule := parse(t, `
title: 1 of identifier
detection:
  selection:
    - Image|endswith: '\cmd.exe'
    - Image|endswith: '\pwsh.exe'
  filter:
    User: admin
  condition: 1 of selection and not all of filter
`)
	e := ForRule(rule)
	ctx := context.Background()
	cases := []struct {
		event map[string]interface{}
		want  bool
	}{
		{map[string]interface{}{"Image": `C:\Windows\cmd.exe`, "User": "bob"}, true},
		{map[string]interface{}{"Image": `C:\Windows\cmd.exe`, "User": "admin"}, false},
		{map[string]interface{}{"Image": `C:\Windows\notepad.exe`, "User": "bob"}, false},
	}
	for _, tc := range cases {
		r, err := e.Matches(ctx, tc.event)
		if err != nil {
			t.Fatal(err)
		}
		if r.Match != tc.want {
			t.Errorf("Matches(%v) = %v, want %v", tc.event, r.Match, tc.want)
		}
	}

	// The near aggregation collects identifiers from these nodes too.
	if ids := collectIdentifiers(rule.Detection.Conditions[0].Search, rule.Detection.Searches); len(ids) != 2 {
		t.Errorf("collectIdentifiers = %v, want selection and filter", ids)
	}
}

// Per the Sigma spec, `1 of them` / `all of them` skip identifiers that start
// with an underscore.
func TestThemExcludesUnderscoreIdentifiers(t *testing.T) {
	oneOf := ForRule(parse(t, `
title: 1 of them
detection:
  sel:
    Image: a.exe
  _helper:
    User: bob
  condition: 1 of them
`))
	allOf := ForRule(parse(t, `
title: all of them
detection:
  sel:
    Image: a.exe
  _helper:
    User: bob
  condition: all of them
`))
	ctx := context.Background()

	// Only the helper matches: it must not satisfy `1 of them` on its own.
	r, err := oneOf.Matches(ctx, map[string]interface{}{"Image": "b.exe", "User": "bob"})
	if err != nil {
		t.Fatal(err)
	}
	if r.Match {
		t.Error("1 of them matched on an underscore-prefixed identifier alone")
	}
	// Only sel matches: `all of them` doesn't require the helper.
	r, err = allOf.Matches(ctx, map[string]interface{}{"Image": "a.exe", "User": "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !r.Match {
		t.Error("all of them required an underscore-prefixed identifier")
	}
}

// Keywords use the Sigma value syntax: `\*` is a literal star and `\\` a single
// backslash, and absent fields don't contribute "<nil>" text.
func TestKeywordEscapesAndNilValues(t *testing.T) {
	rule := parse(t, `
title: keywords
detection:
  keywords:
    - 'literal\*star'
    - 'C:\\Windows\\Temp'
    - 'nil'
  condition: keywords
`)
	e := ForRule(rule)
	ctx := context.Background()
	cases := []struct {
		event map[string]interface{}
		want  bool
	}{
		{map[string]interface{}{"msg": "a literal*star here"}, true},
		{map[string]interface{}{"msg": "a literalXstar here"}, false},
		{map[string]interface{}{"path": `C:\Windows\Temp\x.exe`}, true},
		{map[string]interface{}{"absent": nil}, false},
	}
	for _, tc := range cases {
		r, err := e.Matches(ctx, tc.event)
		if err != nil {
			t.Fatal(err)
		}
		if r.Match != tc.want {
			t.Errorf("Matches(%v) = %v, want %v", tc.event, r.Match, tc.want)
		}
	}
}

// WithEventFilter must stop filtered events before they reach any aggregation
// state, not just hide the match.
func TestEventFilterSkipsAggregationState(t *testing.T) {
	rule := parse(t, `
title: count
detection:
  s:
    EventID: 4625
  timeframe: 10m
  condition: s | count() > 1
`)
	var counted int
	e := ForRule(rule,
		CountImplementation(func(ctx context.Context, key GroupedByValues) (float64, error) {
			counted++
			return float64(counted), nil
		}),
		WithEventFilter(func(r sigma.Rule, event Event) bool {
			return event.(map[string]interface{})["Channel"] == "Security"
		}),
	)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		r, err := e.Matches(ctx, map[string]interface{}{"EventID": 4625, "Channel": "Other"})
		if err != nil {
			t.Fatal(err)
		}
		if r.Match {
			t.Fatal("filtered event matched")
		}
	}
	if counted != 0 {
		t.Fatalf("filtered events reached the count implementation %d time(s)", counted)
	}
	if r, _ := e.Matches(ctx, map[string]interface{}{"EventID": 4625, "Channel": "Security"}); r.Match {
		t.Fatal("first in-scope event should not fire count() > 1")
	}
}

func TestCorrelationValueSum(t *testing.T) {
	c := buildCorrelation(t, `
title: Exfiltration
correlation:
  type: value_sum
  rules: [conn]
  group-by: [User]
  timespan: 1h
  condition:
    field: BytesSent
    gt: 1000
`, `
title: conn
name: conn
detection:
  s:
    EventID: 3
  condition: s
`)
	ctx := context.Background()
	base := time.Now()
	evt := func(user string, bytes interface{}) map[string]interface{} {
		return map[string]interface{}{"EventID": 3, "User": user, "BytesSent": bytes}
	}
	steps := []struct {
		event map[string]interface{}
		at    time.Duration
		want  bool
	}{
		{evt("alice", 600), 0, false},
		{evt("bob", 900), time.Minute, false},           // separate group
		{evt("alice", "n/a"), 2 * time.Minute, false},   // not numeric: ignored
		{evt("alice", "0x12c"), 3 * time.Minute, false}, // 600 + 300 = 900
		{evt("alice", uint32(200)), 4 * time.Minute, true},
	}
	for i, st := range steps {
		res, err := c.matches(ctx, st.event, base.Add(st.at))
		if err != nil {
			t.Fatal(err)
		}
		if res.Match != st.want {
			t.Fatalf("step %d: match = %v, want %v", i, res.Match, st.want)
		}
	}
}

func TestCorrelationValueAvgFractionalThreshold(t *testing.T) {
	c := buildCorrelation(t, `
title: Average
correlation:
  type: value_avg
  rules: [conn]
  timespan: 1h
  condition:
    field: Duration
    gte: 2.5
`, `
title: conn
name: conn
detection:
  s:
    EventID: 3
  condition: s
`)
	ctx := context.Background()
	base := time.Now()
	for i, st := range []struct {
		value float64
		want  bool
	}{
		{2, false}, // avg 2
		{2, false}, // avg 2
		{4, true},  // avg 2.67 >= 2.5
	} {
		res, err := c.matches(ctx, map[string]interface{}{"EventID": 3, "Duration": st.value}, base.Add(time.Duration(i)*time.Second))
		if err != nil {
			t.Fatal(err)
		}
		if res.Match != st.want {
			t.Fatalf("step %d: match = %v, want %v", i, res.Match, st.want)
		}
	}
}

func TestValueSumRequiresField(t *testing.T) {
	_, err := ForCorrelation(parse(t, `
title: Exfiltration
correlation:
  type: value_sum
  rules: [conn]
  timespan: 1h
  condition:
    gt: 1000
`), []sigma.Rule{parse(t, `
title: conn
name: conn
detection:
  s:
    EventID: 3
  condition: s
`)})
	if err == nil {
		t.Fatal("value_sum without condition.field should be rejected")
	}
}
