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
// wildcardMatcher is the compiled form of one rule value: either a plain
// (unescaped) literal, or anchored regexes when the value contains wildcards.
type wildcardMatcher struct {
	literal     string         // the unescaped value; used when there are no wildcards
	sensitive   *regexp.Regexp // nil if the value contains no wildcards
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

// matchWildcard reports whether actual matches the Sigma value expected,
// applying the wildcard and escaping rules above. Values without wildcards are
// compared for (case-insensitive by default) string equality.
func matchWildcard(actual, expected string, caseSensitive bool) bool {
	if !strings.ContainsAny(expected, `*?\`) {
		if caseSensitive {
			return expected == actual
		}
		return strings.EqualFold(expected, actual)
	}

	cached, ok := wildcardMatchers.Load(expected)
	if !ok {
		cached, _ = wildcardMatchers.LoadOrStore(expected, compileWildcard(expected))
	}
	m := cached.(*wildcardMatcher)

	if m.sensitive == nil {
		if caseSensitive {
			return m.literal == actual
		}
		return strings.EqualFold(m.literal, actual)
	}
	if caseSensitive {
		return m.sensitive.MatchString(actual)
	}
	return m.insensitive.MatchString(actual)
}

func compileWildcard(value string) *wildcardMatcher {
	var literal, pattern strings.Builder
	hasWildcard := false
	runes := []rune(value)
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		if r == '\\' && i+1 < len(runes) {
			if next := runes[i+1]; next == '*' || next == '?' || next == '\\' {
				literal.WriteRune(next)
				pattern.WriteString(regexp.QuoteMeta(string(next)))
				i++
				continue
			}
			// A single backslash before a plain character is a plain backslash.
		}
		switch r {
		case '*':
			hasWildcard = true
			pattern.WriteString(".*")
		case '?':
			hasWildcard = true
			pattern.WriteString(".")
		default:
			literal.WriteRune(r)
			pattern.WriteString(regexp.QuoteMeta(string(r)))
		}
	}

	m := &wildcardMatcher{literal: literal.String()}
	if hasWildcard {
		// (?s) so `*`/`?` also span newlines; \A/\z anchor to the whole value.
		m.sensitive = regexp.MustCompile(`(?s)\A` + pattern.String() + `\z`)
		m.insensitive = regexp.MustCompile(`(?is)\A` + pattern.String() + `\z`)
	}
	return m
}
