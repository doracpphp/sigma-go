package sigma

import (
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// A parsed correlation rule must survive a Marshal/Parse round trip: the
// timespan must be re-emitted in Sigma syntax (not nanoseconds) and the
// condition in its {op: count} mapping form (not raw struct fields).
func TestCorrelationRoundTrip(t *testing.T) {
	src := `
title: Brute force
name: brute_force
correlation:
  type: event_count
  rules: [failed_logon]
  group-by: [User]
  timespan: 5m
  condition:
    gte: 3
    lte: 10
`
	rule, err := ParseRule([]byte(src))
	if err != nil {
		t.Fatal(err)
	}
	out, err := yaml.Marshal(rule)
	if err != nil {
		t.Fatal(err)
	}
	reparsed, err := ParseRule(out)
	if err != nil {
		t.Fatalf("re-parsing marshalled rule: %v\n%s", err, out)
	}
	c := reparsed.Correlation
	if c == nil {
		t.Fatal("correlation lost in round trip")
	}
	if c.Timespan.Duration() != 5*time.Minute {
		t.Errorf("timespan lost in round trip: %v", c.Timespan.Duration())
	}
	if len(c.Condition.Terms) != 2 ||
		c.Condition.Terms[0] != (CorrelationConditionTerm{Op: "gte", Count: 3}) ||
		c.Condition.Terms[1] != (CorrelationConditionTerm{Op: "lte", Count: 10}) {
		t.Errorf("condition terms lost in round trip: %+v", c.Condition)
	}
}

// A condition with several operators keeps all of them (AND semantics), with
// Op/Count mirroring the first for backwards compatibility.
func TestCorrelationConditionMultipleOperators(t *testing.T) {
	rule, err := ParseRule([]byte(`
title: range
correlation:
  type: event_count
  rules: [r]
  timespan: 5m
  condition:
    gte: 3
    lte: 5
`))
	if err != nil {
		t.Fatal(err)
	}
	cond := rule.Correlation.Condition
	if len(cond.Terms) != 2 {
		t.Fatalf("expected 2 terms, got %+v", cond.Terms)
	}
	if cond.Op != "gte" || cond.Count != 3 {
		t.Errorf("Op/Count should mirror the first term, got %s/%d", cond.Op, cond.Count)
	}
}

func TestParseTimespanValidation(t *testing.T) {
	for _, invalid := range []string{"-5m", "0s", "5x", "m", "", "99999999999999999999s"} {
		if _, err := ParseTimespan(invalid); err == nil {
			t.Errorf("ParseTimespan(%q) should error", invalid)
		}
	}
	if d, err := ParseTimespan("7d"); err != nil || d != 7*24*time.Hour {
		t.Errorf("ParseTimespan(7d) = %v, %v", d, err)
	}
}

// Integer timeframes (nanoseconds) were accepted by earlier versions via
// yaml.v3's native time.Duration decoding and must keep parsing.
func TestIntegerTimeframe(t *testing.T) {
	rule, err := ParseRule([]byte(`
title: int timeframe
detection:
  s:
    EventID: 1
  timeframe: 3600000000000
  condition: s | count() > 5
`))
	if err != nil {
		t.Fatal(err)
	}
	if rule.Detection.Timeframe != time.Hour {
		t.Errorf("timeframe = %v, want 1h", rule.Detection.Timeframe)
	}
}

// InferFileType must classify by top-level keys, not by scalar values: a config
// whose title happens to be "correlation" is still a config.
func TestInferFileTypeUsesKeysOnly(t *testing.T) {
	config := []byte(`
title: correlation
logsources:
  windows:
    product: windows
`)
	if ft := InferFileType(config); ft != ConfigFile {
		t.Errorf("config with title 'correlation' classified as %q", ft)
	}
	rule := []byte(`
title: a rule
detection:
  s:
    EventID: 1
  condition: s
`)
	if ft := InferFileType(rule); ft != RuleFile {
		t.Errorf("rule classified as %q", ft)
	}
}
