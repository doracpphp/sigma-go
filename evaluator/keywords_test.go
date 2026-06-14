package evaluator

import (
	"context"
	"testing"
)

func TestKeywordSearch(t *testing.T) {
	rule := parse(t, `
title: keyword search
detection:
  keywords:
    - 'mimikatz'
    - 'failed login'
  condition: keywords
`)
	ctx := context.Background()

	cases := []struct {
		name      string
		event     map[string]interface{}
		wantMatch bool
	}{
		{"keyword in one field (substring)", map[string]interface{}{"CommandLine": "C:\\mimikatz.exe -a"}, true},
		{"keyword in a different field", map[string]interface{}{"Image": "x", "Message": "the user had a failed login attempt"}, true},
		{"case-insensitive by default", map[string]interface{}{"CommandLine": "MIMIKATZ"}, true},
		{"no keyword present", map[string]interface{}{"CommandLine": "notepad.exe", "User": "alice"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ForRule(rule).Matches(ctx, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			if res.Match != tc.wantMatch {
				t.Fatalf("got match=%v want %v", res.Match, tc.wantMatch)
			}
		})
	}
}

func TestKeywordWildcards(t *testing.T) {
	rule := parse(t, `
title: keyword wildcard
detection:
  keywords:
    - 'powershell*-enc'
  condition: keywords
`)
	ctx := context.Background()

	cases := []struct {
		name      string
		event     map[string]interface{}
		wantMatch bool
	}{
		{"wildcard spans content", map[string]interface{}{"CommandLine": "powershell.exe -noprofile -enc ABCD"}, true},
		{"missing trailing token", map[string]interface{}{"CommandLine": "powershell.exe -noprofile"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res, err := ForRule(rule).Matches(ctx, tc.event)
			if err != nil {
				t.Fatal(err)
			}
			if res.Match != tc.wantMatch {
				t.Fatalf("got match=%v want %v", res.Match, tc.wantMatch)
			}
		})
	}
}

func TestKeywordCaseSensitive(t *testing.T) {
	rule := parse(t, `
title: keyword cased
detection:
  keywords:
    - 'Mimikatz'
  condition: keywords
`)
	ctx := context.Background()
	event := map[string]interface{}{"CommandLine": "mimikatz"}

	// Default (case-insensitive) matches.
	if res, _ := ForRule(rule).Matches(ctx, event); !res.Match {
		t.Fatal("default keyword search should be case-insensitive")
	}
	// With the CaseSensitive option, the differing case no longer matches.
	if res, _ := ForRule(rule, CaseSensitive).Matches(ctx, event); res.Match {
		t.Fatal("CaseSensitive keyword search should not match different case")
	}
}

func TestKeywordWorksWithStringEvent(t *testing.T) {
	rule := parse(t, `
title: keyword string event
detection:
  keywords:
    - 'denied'
  condition: keywords
`)
	// map[string]string events should also be searched.
	res, err := ForRule(rule).Matches(context.Background(), map[string]string{"action": "access denied for user"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Match {
		t.Fatal("keyword search should work on map[string]string events")
	}
}
