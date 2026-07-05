package modifiers

import (
	"testing"
)

// A field value that YAML parses to null ("", "~", "null") used to make
// coerceNumeric panic on a nil reflect.Type; numeric comparators must return an
// error (treated as non-match) instead.
func TestNumericComparatorNullStrings(t *testing.T) {
	for _, v := range []string{"", "~", "null", "not-a-number"} {
		if _, err := (gt{}).Matches(v, 5); err == nil {
			t.Errorf("gt(%q, 5) should return an error", v)
		}
		if _, err := (lte{}).Matches(3, v); err == nil {
			t.Errorf("lte(3, %q) should return an error", v)
		}
	}
}

// base64offset of a short value produces an empty candidate at some offsets
// (the start/end trims consume the whole base64 group). Empty candidates must
// be dropped: fed into `contains` they match every event.
func TestBase64OffsetShortValueDoesNotMatchEverything(t *testing.T) {
	comparator, err := GetComparator("f", nil, "base64offset", "contains")
	if err != nil {
		t.Fatal(err)
	}
	// Note: the value avoids 'y'/'h', the (case-folded) non-empty candidates for
	// base64offset("a"); the empty candidate would have matched ANY string.
	matched, err := comparator("cmd.exe /c ping", "a")
	if err != nil {
		t.Fatal(err)
	}
	if matched {
		t.Error("base64offset|contains of a 1-byte value must not match unrelated data")
	}
	// The non-empty alignments must still match: base64("a") at offset 0 is "YQ=="
	// which after the end trim leaves the candidate "Y".
	matched, err = comparator("xxxYQ==xxx", "a")
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Error("base64offset|contains should still match data containing the encoded value")
	}
}

// When the evaluator-wide CaseSensitive option supplies the case-sensitive
// comparator set, the default (equality) comparison must be case-sensitive too,
// not only the explicit contains/startswith/endswith modifiers.
func TestCaseSensitiveDefaultComparator(t *testing.T) {
	comparator, err := GetComparator("f", ComparatorsCaseSensitive)
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := comparator("FOO", "foo"); ok {
		t.Error("default equality should be case-sensitive with the case-sensitive comparator set")
	}
	if ok, _ := comparator("foo", "foo"); !ok {
		t.Error("exact match should still match")
	}
}

// The single-value windash path must not rewrite the value: the original is
// itself one of the variants.
func TestWindashModifyPreservesValue(t *testing.T) {
	got, err := ValueModifiers["windash"].Modify("/foo -bar")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/foo -bar" {
		t.Errorf("windash.Modify = %q, want the value unchanged", got)
	}
}

// Regex flag sub-modifiers must immediately follow `re`; anything else is an
// unknown modifier, matching pySigma's behavior.
func TestReFlagAdjacency(t *testing.T) {
	if _, err := GetComparator("f", nil, "re", "cased", "i"); err == nil {
		t.Error("re|cased|i should be rejected: the flag does not immediately follow re")
	}
	comparator, err := GetComparator("f", nil, "re", "i")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := comparator("FOO", "foo"); !ok {
		t.Error("re|i should match case-insensitively")
	}
}

// An invalid rule regex must be reported as an error on every call (not just
// the first), and must not be recompiled every event.
func TestCompileRegexCachesFailures(t *testing.T) {
	for i := 0; i < 2; i++ {
		if _, err := CompileRegex("(unclosed"); err == nil {
			t.Fatalf("call %d: invalid pattern should error", i)
		}
	}
}
