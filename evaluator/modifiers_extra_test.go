package evaluator

import (
	"context"
	"testing"

	"github.com/doracpphp/sigma-go"
)

func mustRule(t *testing.T, y string) sigma.Rule {
	t.Helper()
	r, err := sigma.ParseRule([]byte(y))
	if err != nil {
		t.Fatalf("parse rule: %v", err)
	}
	return r
}

func TestExistsModifier(t *testing.T) {
	existsTrue := mustRule(t, `
title: field present
detection:
  s:
    Image|exists: true
  condition: s
`)
	existsFalse := mustRule(t, `
title: field absent
detection:
  s:
    Image|exists: false
  condition: s
`)
	ctx := context.Background()

	cases := []struct {
		name      string
		rule      sigma.Rule
		event     map[string]interface{}
		wantMatch bool
	}{
		{"exists:true with field present", existsTrue, map[string]interface{}{"Image": "C:\\a.exe"}, true},
		{"exists:true with field absent", existsTrue, map[string]interface{}{"Other": "x"}, false},
		{"exists:false with field present", existsFalse, map[string]interface{}{"Image": "C:\\a.exe"}, false},
		{"exists:false with field absent", existsFalse, map[string]interface{}{"Other": "x"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ForRule(tc.rule).Matches(ctx, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			if res.Match != tc.wantMatch {
				t.Fatalf("got match=%v want %v", res.Match, tc.wantMatch)
			}
		})
	}
}

// A literal `%` value (e.g. `CommandLine|contains: '%'`, a common way to detect
// environment variables) must not be mistaken for a `%name%` placeholder. The bug
// made the whole rule error out ("can't expand %") and get skipped.
func TestLiteralPercentNotPlaceholder(t *testing.T) {
	rule := mustRule(t, `
title: literal percent
detection:
  s:
    CommandLine|contains: '%'
  condition: s
`)
	ctx := context.Background()
	cases := []struct {
		cmd       string
		wantMatch bool
	}{
		{`echo %USERNAME%`, true},
		{`cscript /nologo x.vbs`, false},
	}
	for _, tc := range cases {
		event := map[string]interface{}{"CommandLine": tc.cmd}
		// No placeholder expander configured: must not error.
		res, err := ForRule(rule).Matches(ctx, event)
		if err != nil {
			t.Fatalf("%q: unexpected error: %v", tc.cmd, err)
		}
		if res.Match != tc.wantMatch {
			t.Errorf("%q: single-rule match=%v want %v", tc.cmd, res.Match, tc.wantMatch)
		}
		results, err := ForRules([]sigma.Rule{rule}).Matches(ctx, event)
		if err != nil {
			t.Fatalf("%q: bundle error: %v", tc.cmd, err)
		}
		got := len(results) == 1 && results[0].Match
		if got != tc.wantMatch {
			t.Errorf("%q: bundle match=%v want %v", tc.cmd, got, tc.wantMatch)
		}
	}
}

// `windash|contains` must work in the batch bundle path: the value modifier
// expands `-c` into `/c` etc., and those expansions must be in the Aho-Corasick
// needle set, otherwise the bundle misses events that use a non-hyphen variant.
func TestWindashContainsBundle(t *testing.T) {
	rule := mustRule(t, `
title: windash contains
detection:
  s:
    ImagePath|contains|windash: ' -c '
  condition: s
`)
	ctx := context.Background()
	// Event uses "/c" (a windash variant of "-c").
	event := map[string]interface{}{"ImagePath": `C:\Windows\System32\cmd.exe /c powershell`}

	single, err := ForRule(rule).Matches(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	results, err := ForRules([]sigma.Rule{rule}).Matches(ctx, event)
	if err != nil {
		t.Fatal(err)
	}
	bundle := len(results) == 1 && results[0].Match
	if !single.Match || !bundle {
		t.Fatalf("windash|contains '/c': single=%v bundle=%v, want both true", single.Match, bundle)
	}
}

// A contains value with a wildcard and a trailing backslash (e.g.
// `>?C:\Windows\Temp\`) must match. Padding the value with a literal `*` used to
// turn the trailing `\` + `*` into an escaped `\*`, breaking the match.
func TestWildcardContainsTrailingBackslash(t *testing.T) {
	rule := mustRule(t, `
title: trailing backslash
detection:
  s:
    CommandLine|contains:
      - '>?C:\Windows\Temp\'
  condition: s
`)
	ctx := context.Background()
	cases := []struct {
		name      string
		cmd       string
		wantMatch bool
	}{
		{"redirect into temp", `cmd.exe /C whoami > C:\Windows\Temp\x.tmp 2>&1`, true},
		{"different dir does not match", `cmd.exe /C whoami > C:\Users\bob\x.tmp`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			event := map[string]interface{}{"CommandLine": tc.cmd}
			single, _ := ForRule(rule).Matches(ctx, event)
			results, _ := ForRules([]sigma.Rule{rule}).Matches(ctx, event)
			bundle := len(results) == 1 && results[0].Match
			if single.Match != tc.wantMatch || bundle != tc.wantMatch {
				t.Fatalf("single=%v bundle=%v, want %v", single.Match, bundle, tc.wantMatch)
			}
		})
	}
}

// Wildcards (`*`/`?`) inside contains/startswith/endswith values must be honoured
// in both the single-rule path and the batch bundle path (whose Aho-Corasick
// contains optimisation can't handle wildcards and must fall back).
func TestContainsWildcards(t *testing.T) {
	rule := mustRule(t, `
title: contains wildcard
detection:
  s:
    CommandLine|contains: 'foo*bar'
  condition: s
`)
	ctx := context.Background()

	cases := []struct {
		name      string
		event     map[string]interface{}
		wantMatch bool
	}{
		{"wildcard spans middle", map[string]interface{}{"CommandLine": "x fooXXXbar y"}, true},
		{"adjacent (star matches empty)", map[string]interface{}{"CommandLine": "x foobar y"}, true},
		{"wrong tail", map[string]interface{}{"CommandLine": "x foobaz y"}, false},
	}
	for _, tc := range cases {
		t.Run("single/"+tc.name, func(t *testing.T) {
			res, err := ForRule(rule).Matches(ctx, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			if res.Match != tc.wantMatch {
				t.Fatalf("single-rule: got match=%v want %v", res.Match, tc.wantMatch)
			}
		})
		t.Run("bundle/"+tc.name, func(t *testing.T) {
			results, err := ForRules([]sigma.Rule{rule}).Matches(ctx, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			got := len(results) == 1 && results[0].Match
			if got != tc.wantMatch {
				t.Fatalf("bundle: got match=%v want %v", got, tc.wantMatch)
			}
		})
	}
}

func TestFieldRefModifier(t *testing.T) {
	// Match when TargetFilename equals the value of another field, SourceFilename.
	ruleEq := mustRule(t, `
title: fieldref equality
detection:
  s:
    TargetFilename|fieldref: SourceFilename
  condition: s
`)
	// fieldref combined with a comparator: Domain must be a suffix of Fqdn.
	ruleEndswith := mustRule(t, `
title: fieldref endswith
detection:
  s:
    Fqdn|endswith|fieldref: Domain
  condition: s
`)
	ctx := context.Background()

	cases := []struct {
		name      string
		rule      sigma.Rule
		event     map[string]interface{}
		wantMatch bool
	}{
		{"equal fields match", ruleEq, map[string]interface{}{"TargetFilename": "a.txt", "SourceFilename": "a.txt"}, true},
		{"different fields don't match", ruleEq, map[string]interface{}{"TargetFilename": "a.txt", "SourceFilename": "b.txt"}, false},
		{"referenced field absent", ruleEq, map[string]interface{}{"TargetFilename": "a.txt"}, false},
		{"endswith fieldref match", ruleEndswith, map[string]interface{}{"Fqdn": "host.example.com", "Domain": "example.com"}, true},
		{"endswith fieldref no match", ruleEndswith, map[string]interface{}{"Fqdn": "host.example.com", "Domain": "evil.com"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ForRule(tc.rule).Matches(ctx, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			if res.Match != tc.wantMatch {
				t.Fatalf("got match=%v want %v", res.Match, tc.wantMatch)
			}
		})
	}
}

func TestCasedModifierEndToEnd(t *testing.T) {
	cased := mustRule(t, `
title: cased exact
detection:
  s:
    CommandLine|cased: 'PowerShell.EXE'
  condition: s
`)
	casedContains := mustRule(t, `
title: cased contains
detection:
  s:
    CommandLine|contains|cased: 'Mimikatz'
  condition: s
`)
	ctx := context.Background()

	cases := []struct {
		name      string
		rule      sigma.Rule
		event     map[string]interface{}
		wantMatch bool
	}{
		{"cased exact same case", cased, map[string]interface{}{"CommandLine": "PowerShell.EXE"}, true},
		{"cased exact different case", cased, map[string]interface{}{"CommandLine": "powershell.exe"}, false},
		{"cased contains same case", casedContains, map[string]interface{}{"CommandLine": "x Mimikatz y"}, true},
		{"cased contains different case", casedContains, map[string]interface{}{"CommandLine": "x mimikatz y"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ForRule(tc.rule).Matches(ctx, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			if res.Match != tc.wantMatch {
				t.Fatalf("got match=%v want %v", res.Match, tc.wantMatch)
			}
		})
	}
}

func TestExpandModifier(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: expand modifier
detection:
  selection:
    User|expand: '%admins%'
  condition: selection
`))
	if err != nil {
		t.Fatal(err)
	}
	e := ForRule(rule, WithPlaceholderExpander(func(ctx context.Context, name string) ([]string, error) {
		if name == "%admins%" {
			return []string{"alice", "bob"}, nil
		}
		return nil, nil
	}))

	result, err := e.Matches(context.Background(), map[string]interface{}{"User": "alice"})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Match {
		t.Error("expected expanded placeholder to match alice")
	}

	result, err = e.Matches(context.Background(), map[string]interface{}{"User": "mallory"})
	if err != nil {
		t.Fatal(err)
	}
	if result.Match {
		t.Error("mallory is not in the expanded placeholder values")
	}
}

// A placeholder embedded inside a larger value must be expanded in place, with the
// surrounding literal text preserved (and the cartesian product taken when several
// placeholders appear).
func TestExpandModifierEmbedded(t *testing.T) {
	rule := mustRule(t, `
title: embedded expand
detection:
  selection:
    Image|expand: 'C:\Users\%user%\AppData\%tool%.exe'
  condition: selection
`)
	expander := WithPlaceholderExpander(func(ctx context.Context, name string) ([]string, error) {
		switch name {
		case "%user%":
			return []string{"alice", "bob"}, nil
		case "%tool%":
			return []string{"mimikatz"}, nil
		}
		return nil, nil
	})
	e := ForRule(rule, expander)
	ctx := context.Background()

	cases := []struct {
		name      string
		image     string
		wantMatch bool
	}{
		{"first user", `C:\Users\alice\AppData\mimikatz.exe`, true},
		{"second user", `C:\Users\bob\AppData\mimikatz.exe`, true},
		{"unknown user", `C:\Users\carol\AppData\mimikatz.exe`, false},
		{"wrong tool", `C:\Users\alice\AppData\notepad.exe`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := e.Matches(ctx, map[string]interface{}{"Image": tc.image})
			if err != nil {
				t.Fatal(err)
			}
			if res.Match != tc.wantMatch {
				t.Fatalf("got match=%v want %v", res.Match, tc.wantMatch)
			}
		})
	}

	// Without the expand modifier, an embedded `%...%` is treated literally.
	literalRule := mustRule(t, `
title: literal percent
detection:
  selection:
    Image: 'C:\Users\%user%\x.exe'
  condition: selection
`)
	res, err := ForRule(literalRule, expander).Matches(ctx, map[string]interface{}{"Image": `C:\Users\%user%\x.exe`})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Match {
		t.Error("without expand modifier, embedded %user% should be matched literally")
	}
}

// Timestamp component modifiers (minute/hour/day/week/month/year) parse the event
// field as a timestamp and compare the extracted component to the rule's number.
func TestTimestampModifiers(t *testing.T) {
	ctx := context.Background()
	rule := func(mod, val string) sigma.Rule {
		return mustRule(t, `
title: timestamp
detection:
  selection:
    Timestamp|`+mod+`: `+val+`
  condition: selection
`)
	}

	// 2021-03-15 14:30:00 UTC is a Monday in ISO week 11.
	const ts = "2021-03-15T14:30:00Z"

	cases := []struct {
		name      string
		rule      sigma.Rule
		event     map[string]interface{}
		wantMatch bool
	}{
		{"hour match", rule("hour", "14"), map[string]interface{}{"Timestamp": ts}, true},
		{"hour mismatch", rule("hour", "15"), map[string]interface{}{"Timestamp": ts}, false},
		{"minute match", rule("minute", "30"), map[string]interface{}{"Timestamp": ts}, true},
		{"day match", rule("day", "15"), map[string]interface{}{"Timestamp": ts}, true},
		{"month match", rule("month", "3"), map[string]interface{}{"Timestamp": ts}, true},
		{"year match", rule("year", "2021"), map[string]interface{}{"Timestamp": ts}, true},
		{"iso week match", rule("week", "11"), map[string]interface{}{"Timestamp": ts}, true},
		{"space-separated layout", rule("hour", "14"), map[string]interface{}{"Timestamp": "2021-03-15 14:30:00"}, true},
		{"unparseable value is no match", rule("hour", "14"), map[string]interface{}{"Timestamp": "not-a-timestamp"}, false},
		{"epoch zero -> 1970", rule("year", "1970"), map[string]interface{}{"Timestamp": 0}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ForRule(tc.rule).Matches(ctx, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			if res.Match != tc.wantMatch {
				t.Fatalf("got match=%v want %v", res.Match, tc.wantMatch)
			}
		})
	}

	// Composed with a numeric comparator: business-hours style `hour|gte`.
	gte := mustRule(t, `
title: hour gte
detection:
  selection:
    Timestamp|hour|gte: 9
  condition: selection
`)
	for _, tc := range []struct {
		ts        string
		wantMatch bool
	}{
		{"2021-03-15T14:00:00Z", true},
		{"2021-03-15T08:00:00Z", false},
	} {
		res, err := ForRule(gte).Matches(ctx, map[string]interface{}{"Timestamp": tc.ts})
		if err != nil {
			t.Fatal(err)
		}
		if res.Match != tc.wantMatch {
			t.Fatalf("hour|gte 9 on %s: got match=%v want %v", tc.ts, res.Match, tc.wantMatch)
		}
	}
}

// An absent field must never match contains/startswith/endswith, even with a
// wildcard value like `*`. Regression test for over-matching where a `ps_module`
// rule's `ContextInfo|contains: '*'` fired on every event whose ContextInfo field
// was absent (nil coerces to the non-empty string "<nil>").
func TestContainsAbsentFieldNeverMatches(t *testing.T) {
	ctx := context.Background()
	rules := map[string]sigma.Rule{
		"contains star": mustRule(t, `
title: contains star
detection:
  selection:
    ContextInfo|contains: '*'
  condition: selection
`),
		"contains plain": mustRule(t, `
title: contains plain
detection:
  selection:
    ContextInfo|contains: 'powershell'
  condition: selection
`),
		"startswith star": mustRule(t, `
title: startswith star
detection:
  selection:
    ContextInfo|startswith: '*'
  condition: selection
`),
		"endswith star": mustRule(t, `
title: endswith star
detection:
  selection:
    ContextInfo|endswith: '*'
  condition: selection
`),
	}

	// Event without the ContextInfo field at all.
	absent := map[string]interface{}{"Image": "C:\\Windows\\System32\\cmd.exe"}
	// Event where ContextInfo is present (so `*` legitimately matches).
	present := map[string]interface{}{"ContextInfo": "Host Application = powershell.exe"}

	for name, rule := range rules {
		// Absent field: must not match in either the single-rule or bundle path.
		if res, err := ForRule(rule).Matches(ctx, absent); err != nil {
			t.Fatal(err)
		} else if res.Match {
			t.Errorf("%s: absent ContextInfo should not match (single-rule)", name)
		}
		if results, err := ForRules([]sigma.Rule{rule}).Matches(ctx, absent); err != nil {
			t.Fatal(err)
		} else if len(results) == 1 && results[0].Match {
			t.Errorf("%s: absent ContextInfo should not match (bundle)", name)
		}
	}

	// A present ContextInfo still matches the wildcard rules (sanity check that the
	// guard didn't over-correct).
	if res, _ := ForRule(rules["contains star"]).Matches(ctx, present); !res.Match {
		t.Error("present ContextInfo should still match contains '*'")
	}
}

// `neq` is pySigma's SigmaNegateModifier: it negates the field match (NOT match),
// works on any value type, and composes with comparators and any/all linking. It
// must behave identically in the single-rule and bundle paths.
func TestNeqModifier(t *testing.T) {
	ctx := context.Background()

	// Plain neq: User != "root".
	plain := mustRule(t, `
title: neq plain
detection:
  selection:
    User|neq: 'root'
  condition: selection
`)
	// neq over a list is the negation of the OR: User != alice AND User != bob.
	list := mustRule(t, `
title: neq list
detection:
  selection:
    User|neq:
      - 'alice'
      - 'bob'
  condition: selection
`)
	// neq composed with contains: CommandLine does NOT contain "mimikatz".
	withContains := mustRule(t, `
title: neq contains
detection:
  selection:
    CommandLine|contains|neq: 'mimikatz'
  condition: selection
`)

	cases := []struct {
		name      string
		rule      sigma.Rule
		event     map[string]interface{}
		wantMatch bool
	}{
		{"plain different value matches", plain, map[string]interface{}{"User": "alice"}, true},
		{"plain equal value excluded", plain, map[string]interface{}{"User": "root"}, false},
		{"list neither matches", list, map[string]interface{}{"User": "carol"}, true},
		{"list one member excluded", list, map[string]interface{}{"User": "bob"}, false},
		{"contains absent substring matches", withContains, map[string]interface{}{"CommandLine": "powershell.exe"}, true},
		{"contains present substring excluded", withContains, map[string]interface{}{"CommandLine": "x mimikatz y"}, false},
	}
	for _, tc := range cases {
		t.Run("single/"+tc.name, func(t *testing.T) {
			res, err := ForRule(tc.rule).Matches(ctx, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			if res.Match != tc.wantMatch {
				t.Fatalf("single-rule: got match=%v want %v", res.Match, tc.wantMatch)
			}
		})
		t.Run("bundle/"+tc.name, func(t *testing.T) {
			results, err := ForRules([]sigma.Rule{tc.rule}).Matches(ctx, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			got := len(results) == 1 && results[0].Match
			if got != tc.wantMatch {
				t.Fatalf("bundle: got match=%v want %v", got, tc.wantMatch)
			}
		})
	}
}
