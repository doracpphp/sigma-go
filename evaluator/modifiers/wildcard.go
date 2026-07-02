package modifiers

import (
	"regexp"
	"strings"
	"sync"
)

// The Sigma specification defines that unescaped `*` (any number of characters)
// and `?` (any single character) in plain values are wildcards, with backslash
// as the escape character:
//
//   - `\*` / `\?` is a literal wildcard character
//   - `\\` is a plain backslash (a single `\` before a non-wildcard is also plain)
//   - `\\*` is a plain backslash followed by a wildcard
//   - `\\\*` is a plain backslash followed by a literal `*`
//
// wildcardMatcher is the compiled form of one rule value containing wildcards:
// its anchored case-sensitive and case-insensitive regexes. Values without
// wildcards never reach the cache (matchWildcard compares them directly).
type wildcardMatcher struct {
	sensitive   *regexp.Regexp
	insensitive *regexp.Regexp
}

// wildcardMatchers caches compiled values. Values come from rules (and
// placeholder expansions) so the cardinality is bounded by the loaded ruleset.
var wildcardMatchers sync.Map // map[string]*wildcardMatcher

// HasUnescapedWildcard reports whether s contains a Sigma wildcard (`*` or `?`)
// that is not escaped by a preceding backslash. The contains/startswith/endswith
// comparators use it to decide whether a value needs full wildcard matching or
// can take the faster plain-substring path.
func HasUnescapedWildcard(s string) bool {
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++ // skip the escaped character
		case '*', '?':
			return true
		}
	}
	return false
}

// UnescapeValue resolves the escape sequences above into the literal string
// they denote: `\*` -> `*`, `\?` -> `?`, `\\` -> `\`; a backslash before any
// other character is a plain backslash and is kept. It must only be applied to
// values without unescaped wildcards (see HasUnescapedWildcard).
func UnescapeValue(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '\\' && i+1 < len(s) {
			if next := s[i+1]; next == '*' || next == '?' || next == '\\' {
				b.WriteByte(next)
				i++
				continue
			}
		}
		b.WriteByte(c)
	}
	return b.String()
}

// EscapeValue is the inverse of UnescapeValue: it escapes every `*`, `?` and
// `\` in s so the result is matched as the literal string s by the wildcard
// engine. Used for values that come from event data (fieldref), which must
// never be interpreted as patterns.
func EscapeValue(s string) string {
	if !strings.ContainsAny(s, `*?\`) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) * 2)
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '*', '?', '\\':
			b.WriteByte('\\')
			b.WriteByte(c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// matchWildcard reports whether actual matches the Sigma value expected,
// applying the wildcard and escaping rules above. Values without wildcards are
// compared for (case-insensitive by default) string equality; this path never
// touches the pattern cache, so event-derived values (fieldref) can't grow it.
func matchWildcard(actual, expected string, caseSensitive bool) bool {
	if !HasUnescapedWildcard(expected) {
		literal := UnescapeValue(expected)
		if caseSensitive {
			return literal == actual
		}
		return strings.EqualFold(literal, actual)
	}

	cached, ok := wildcardMatchers.Load(expected)
	if !ok {
		cached, _ = wildcardMatchers.LoadOrStore(expected, compileWildcard(expected))
	}
	m := cached.(*wildcardMatcher)

	if caseSensitive {
		return m.sensitive.MatchString(actual)
	}
	return m.insensitive.MatchString(actual)
}

func compileWildcard(value string) *wildcardMatcher {
	// (?s) so `*`/`?` also span newlines; \A/\z anchor to the whole value.
	pattern := wildcardRegexpBody(value)
	return &wildcardMatcher{
		sensitive:   regexp.MustCompile(`(?s)\A` + pattern + `\z`),
		insensitive: regexp.MustCompile(`(?is)\A` + pattern + `\z`),
	}
}

// affixKind selects how a contains/startswith/endswith value is anchored.
type affixKind int

const (
	affixContains affixKind = iota // value may appear anywhere
	affixPrefix                    // value must match at the start
	affixSuffix                    // value must match at the end
)

type affixKey struct {
	value         string
	kind          affixKind
	caseSensitive bool
}

var affixMatchers sync.Map // map[affixKey]*regexp.Regexp

// matchAffix reports whether actual contains / starts with / ends with the Sigma
// value (which may contain wildcards), per kind. Unlike padding the value with a
// literal `*` (which merges with a trailing backslash into an escaped `\*`), this
// compiles the value to a regexp body and anchors it at the regexp level, so values
// like `>?C:\Windows\Temp\` match correctly.
func matchAffix(actual, value string, kind affixKind, caseSensitive bool) bool {
	key := affixKey{value, kind, caseSensitive}
	cached, ok := affixMatchers.Load(key)
	if !ok {
		cached, _ = affixMatchers.LoadOrStore(key, compileAffix(value, kind, caseSensitive))
	}
	return cached.(*regexp.Regexp).MatchString(actual)
}

func compileAffix(value string, kind affixKind, caseSensitive bool) *regexp.Regexp {
	flags := "(?s)"
	if !caseSensitive {
		flags = "(?is)"
	}
	body := wildcardRegexpBody(value)
	switch kind {
	case affixPrefix:
		body = `\A` + body
	case affixSuffix:
		body = body + `\z`
	}
	// affixContains: no anchors, so MatchString finds the body anywhere.
	return regexp.MustCompile(flags + body)
}

// wildcardRegexpBody converts a Sigma value into the body of a regexp (no anchors),
// applying the same wildcard (`*`/`?`) and backslash-escaping rules as
// compileWildcard. Kept separate so the affix matchers can anchor it themselves.
func wildcardRegexpBody(value string) string {
	var pattern strings.Builder
	runes := []rune(value)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '\\' && i+1 < len(runes) {
			if next := runes[i+1]; next == '*' || next == '?' || next == '\\' {
				pattern.WriteString(regexp.QuoteMeta(string(next)))
				i++
				continue
			}
			// A single backslash before a plain character is a plain backslash.
		}
		switch r {
		case '*':
			pattern.WriteString(".*")
		case '?':
			pattern.WriteString(".")
		default:
			pattern.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return pattern.String()
}
