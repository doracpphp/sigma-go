package evaluator

import (
	"context"
	"testing"

	"github.com/doracpphp/sigma-go"
)

func condition(field, value string) sigma.Search {
	return sigma.Search{
		EventMatchers: []sigma.EventMatcher{
			{{Field: field, Values: []interface{}{value}}},
		},
	}
}

func twoConditionConfig(merging sigma.LogsourceMerging) sigma.Config {
	return sigma.Config{
		LogsourceMerging: merging,
		Logsources: map[string]sigma.LogsourceMapping{
			"a": {
				Logsource:  sigma.Logsource{Category: "category"},
				Index:      []string{"idx"},
				Conditions: condition("foo", "bar"),
			},
			"b": {
				Logsource:  sigma.Logsource{Category: "category"},
				Conditions: condition("baz", "qux"),
			},
		},
	}
}

func TestLogsourceMerging(t *testing.T) {
	ctx := context.Background()
	rule := sigma.Rule{Logsource: sigma.Logsource{Category: "category"}}
	onlyFoo := map[string]interface{}{"foo": "bar"} // satisfies one condition only

	t.Run("and requires all conditions (default)", func(t *testing.T) {
		e := ForRule(rule, WithConfig(twoConditionConfig(sigma.LogsourceMergeAnd)))
		relevant, err := e.RelevantToEvent(ctx, "idx", onlyFoo)
		if err != nil {
			t.Fatal(err)
		}
		if relevant {
			t.Fatal("and merging should require both conditions")
		}
	})

	t.Run("or requires any condition", func(t *testing.T) {
		e := ForRule(rule, WithConfig(twoConditionConfig(sigma.LogsourceMergeOr)))
		relevant, err := e.RelevantToEvent(ctx, "idx", onlyFoo)
		if err != nil {
			t.Fatal(err)
		}
		if !relevant {
			t.Fatal("or merging should match when any condition matches")
		}
	})

	t.Run("default empty merging behaves as and", func(t *testing.T) {
		e := ForRule(rule, WithConfig(twoConditionConfig("")))
		relevant, _ := e.RelevantToEvent(ctx, "idx", onlyFoo)
		if relevant {
			t.Fatal("default merging should behave as and")
		}
		// Satisfying both conditions is relevant under and.
		relevant, _ = e.RelevantToEvent(ctx, "idx", map[string]interface{}{"foo": "bar", "baz": "qux"})
		if !relevant {
			t.Fatal("both conditions satisfied should be relevant")
		}
	})
}

func TestIndexWildcardMatching(t *testing.T) {
	ctx := context.Background()
	rule := ForRule(sigma.Rule{Logsource: sigma.Logsource{Category: "category"}},
		WithConfig(sigma.Config{
			Logsources: map[string]sigma.LogsourceMapping{
				"win": {
					Logsource: sigma.Logsource{Category: "category"},
					Index:     []string{"winlog-*"},
				},
			},
		}))

	if relevant, _ := rule.RelevantToEvent(ctx, "winlog-security", nil); !relevant {
		t.Fatal("winlog-security should match index pattern winlog-*")
	}
	if relevant, _ := rule.RelevantToEvent(ctx, "syslog-1", nil); relevant {
		t.Fatal("syslog-1 should not match index pattern winlog-*")
	}
}

func TestLogsourceMergingParsedFromYAML(t *testing.T) {
	config, err := sigma.ParseConfig([]byte(`
title: test config
logsourcemerging: or
logsources:
  example:
    category: category
    index: idx
`))
	if err != nil {
		t.Fatal(err)
	}
	if config.LogsourceMerging != sigma.LogsourceMergeOr {
		t.Fatalf("expected logsourcemerging 'or', got %q", config.LogsourceMerging)
	}
}
