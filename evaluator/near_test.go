package evaluator

import (
	"context"
	"testing"
	"time"
)

func TestNearAggregation(t *testing.T) {
	rule := parse(t, `
title: near test
detection:
  selection:
    EventID: 1
  filter:
    EventID: 2
  condition: selection | near filter
  timeframe: 5m
`)
	ctx := context.Background()
	base := time.Now()

	t.Run("fires when both match within timeframe", func(t *testing.T) {
		e := ForRule(rule)
		var now time.Time
		e.nowFunc = func() time.Time { return now }

		// filter matches first (selection doesn't, so no fire yet).
		now = base
		res, _ := e.Matches(ctx, map[string]interface{}{"EventID": 2})
		if res.Match {
			t.Fatal("only filter matched, should not fire")
		}
		// selection matches 1 minute later, within the 5m window -> fires.
		now = base.Add(1 * time.Minute)
		res, _ = e.Matches(ctx, map[string]interface{}{"EventID": 1})
		if !res.Match {
			t.Fatal("selection near filter within timeframe should fire")
		}
	})

	t.Run("does not fire when the other search never matched", func(t *testing.T) {
		e := ForRule(rule)
		now := base
		e.nowFunc = func() time.Time { return now }
		res, _ := e.Matches(ctx, map[string]interface{}{"EventID": 1})
		if res.Match {
			t.Fatal("filter never matched, near should not fire")
		}
	})

	t.Run("does not fire when the other match aged out", func(t *testing.T) {
		e := ForRule(rule)
		var now time.Time
		e.nowFunc = func() time.Time { return now }

		now = base
		e.Matches(ctx, map[string]interface{}{"EventID": 2}) // filter at t=0
		now = base.Add(6 * time.Minute)                      // beyond 5m window
		res, _ := e.Matches(ctx, map[string]interface{}{"EventID": 1})
		if res.Match {
			t.Fatal("filter match aged out of the window, near should not fire")
		}
	})
}

func TestNearSingleEventMatchesBoth(t *testing.T) {
	rule := parse(t, `
title: near single event
detection:
  selection:
    A: 1
  filter:
    B: 1
  condition: selection | near filter
  timeframe: 5m
`)
	e := ForRule(rule)
	res, err := e.Matches(context.Background(), map[string]interface{}{"A": 1, "B": 1})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Match {
		t.Fatal("an event matching both searches should fire near")
	}
}

func TestNearWithConjunction(t *testing.T) {
	rule := parse(t, `
title: near conjunction
detection:
  selection:
    EventID: 1
  filterA:
    EventID: 2
  filterB:
    EventID: 3
  condition: selection | near filterA and filterB
  timeframe: 5m
`)
	ctx := context.Background()
	base := time.Now()

	e := ForRule(rule)
	var now time.Time
	e.nowFunc = func() time.Time { return now }

	// Only filterA seen, then selection -> not all near searches matched.
	now = base
	e.Matches(ctx, map[string]interface{}{"EventID": 2})
	now = base.Add(1 * time.Minute)
	res, _ := e.Matches(ctx, map[string]interface{}{"EventID": 1})
	if res.Match {
		t.Fatal("filterB not matched yet, conjunction near should not fire")
	}

	// Now filterB matches too, then selection again -> fires.
	now = base.Add(2 * time.Minute)
	e.Matches(ctx, map[string]interface{}{"EventID": 3})
	now = base.Add(3 * time.Minute)
	res, _ = e.Matches(ctx, map[string]interface{}{"EventID": 1})
	if !res.Match {
		t.Fatal("filterA and filterB both within window, near should fire")
	}
}
