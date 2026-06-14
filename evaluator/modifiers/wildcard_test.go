package modifiers

import "testing"

func TestWildcardMatching(t *testing.T) {
	tests := []struct {
		expected      string
		actual        string
		caseSensitive bool
		want          bool
	}{
		// Plain wildcards
		{`*\lsass.dmp`, `C:\temp\lsass.dmp`, false, true},
		{`*\lsass.dmp`, `C:\temp\lsass_dmp`, false, false},
		{`*\lsass.dmp`, `\lsass.dmp`, false, true},
		{`mimi?atz`, `mimikatz`, false, true},
		{`mimi?atz`, `mimikaatz`, false, false},
		{`*`, `anything`, false, true},
		{`*`, ``, false, true},

		// Wildcards are anchored: the value must match in full
		{`lsass`, `C:\lsass.dmp`, false, false},
		{`*lsass`, `C:\lsass.dmp`, false, false},

		// `*` spans path separators and newlines (note: a backslash followed by a
		// wildcard must be written `\\*`; `\*` would be a literal asterisk)
		{`C:\\*\cmd.exe`, "C:\\a\nb\\cmd.exe", false, true},
		{`C:\*\cmd.exe`, `C:*\cmd.exe`, false, true},

		// Escaping rules from the Sigma specification
		{`a\*b`, `a*b`, false, true},        // \* is a literal asterisk
		{`a\*b`, `axb`, false, false},       // ... and not a wildcard
		{`a\?b`, `a?b`, false, true},        // \? is a literal question mark
		{`a\\*`, `a\anything`, false, true}, // \\* is a backslash then a wildcard
		{`a\\\*`, `a\*`, false, true},       // \\\* is a backslash then a literal *
		{`a\\\*`, `a\anything`, false, false},
		{`C:\Windows\cmd.exe`, `C:\Windows\cmd.exe`, false, true},   // plain backslashes are literal
		{`C:\\Windows\\cmd.exe`, `C:\Windows\cmd.exe`, false, true}, // double backslash is also a plain backslash

		// Case sensitivity
		{`*\LSASS.dmp`, `C:\temp\lsass.dmp`, false, true},
		{`*\LSASS.dmp`, `C:\temp\lsass.dmp`, true, false},
		{`Foo`, `foo`, false, true},
		{`Foo`, `foo`, true, false},
	}
	for _, tt := range tests {
		if got := matchWildcard(tt.actual, tt.expected, tt.caseSensitive); got != tt.want {
			t.Errorf("matchWildcard(%q, %q, cased=%v) = %v, want %v", tt.actual, tt.expected, tt.caseSensitive, got, tt.want)
		}
	}
}

func TestHasUnescapedWildcard(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{`foo`, false},
		{`foo*bar`, true},
		{`foo?bar`, true},
		{`C:\Windows\System32`, false}, // backslashes, no wildcards
		{`foo\*bar`, false},            // escaped `*` is literal
		{`foo\?bar`, false},            // escaped `?` is literal
		{`foo\\*bar`, true},            // escaped backslash, then a real wildcard
		{``, false},
	}
	for _, tt := range tests {
		if got := HasUnescapedWildcard(tt.s); got != tt.want {
			t.Errorf("HasUnescapedWildcard(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

// The contains/startswith/endswith comparators must honour `*`/`?` wildcards
// inside the rule value (matching pySigma) while keeping the fast plain path for
// wildcard-free values.
func TestAffixComparatorsWildcards(t *testing.T) {
	tests := []struct {
		name     string
		cmp      Comparator
		actual   string
		expected string
		want     bool
	}{
		{"contains plain match", contains{}, "x foobar y", "oba", true},
		{"contains star match", contains{}, "alpha-foo-bar-beta", "foo*bar", true},
		{"contains star no match", contains{}, "alpha-foo-baz", "foo*bar", false},
		{"contains question match", contains{}, "a-fXo-b", "fXo", true},
		{"contains question wildcard", contains{}, "a-fXo-b", "f?o", true},
		{"contains escaped star not wildcard", contains{}, "a fooXbar b", `foo\*bar`, false}, // \* is not a wildcard
		{"startswith wildcard match", startswith{}, "fooXXbar tail", "foo*bar", true},
		{"startswith wildcard anchored", startswith{}, "pre foo bar", "foo*bar", false},
		{"endswith wildcard match", endswith{}, "head fooZZbar", "foo*bar", true},
		{"endswith wildcard anchored", endswith{}, "fooZZbar tail", "foo*bar", false},
		{"contains CS star is wildcard", containsCS{}, "x FooXBar y", "Foo*Bar", true},
		{"contains CS wildcard match", containsCS{}, "x FooMidBar y", "Foo*Bar", true},
		{"contains CS wildcard case", containsCS{}, "x fooMidbar y", "Foo*Bar", false},
	}
	for _, tt := range tests {
		got, err := tt.cmp.Matches(tt.actual, tt.expected)
		if err != nil {
			t.Fatalf("%s: unexpected error: %v", tt.name, err)
		}
		if got != tt.want {
			t.Errorf("%s: Matches(%q, %q) = %v, want %v", tt.name, tt.actual, tt.expected, got, tt.want)
		}
	}
}

func TestBaseComparatorNilField(t *testing.T) {
	// A missing field (nil) matches the special value "null" and nothing else,
	// including the bare `*` wildcard which requires the field to have a value.
	if ok, _ := (baseComparator{}).Matches(nil, "null"); !ok {
		t.Error("nil field should match null")
	}
	if ok, _ := (baseComparator{}).Matches(nil, "*"); ok {
		t.Error("nil field should not match *")
	}
	if ok, _ := (baseComparator{}).Matches(nil, "<nil>"); ok {
		t.Error("nil field should not match the string \"<nil>\"")
	}
}
