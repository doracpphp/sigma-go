package modifiers

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf16"

	"gopkg.in/yaml.v3"
)

func GetComparator(field string, comparators map[string]Comparator, modifiers ...string) (ComparatorFunc, error) {
	// `cased` forces case-sensitive matching for this field, overriding the
	// evaluator-wide default. Pull it out before processing the remaining modifiers.
	caseSensitive := false
	var filteredModifiers []string
	for _, modifier := range modifiers {
		if modifier == "cased" {
			caseSensitive = true
			continue
		}
		filteredModifiers = append(filteredModifiers, modifier)
	}
	modifiers = filteredModifiers

	// The `re` comparator accepts regex flag sub-modifiers that immediately follow
	// it. pySigma accepts both short (re|i, re|m, re|s) and long (re|ignorecase,
	// re|multiline, re|dotall) forms; both are normalised to the single inline-flag
	// character here. Pull them out into a flag string and drop them from the
	// modifier list so the remaining `re` is treated as a normal trailing comparator.
	reFlags := ""
	var withoutFlags []string
	for _, modifier := range modifiers {
		if flag, ok := reFlagChar(modifier); ok &&
			len(withoutFlags) > 0 && withoutFlags[len(withoutFlags)-1] == "re" {
			reFlags += flag
			continue
		}
		withoutFlags = append(withoutFlags, modifier)
	}
	modifiers = withoutFlags

	defaultComparator := Comparator(baseComparator{})
	if caseSensitive {
		comparators = ComparatorsCaseSensitive
		defaultComparator = baseComparatorCased{}
	} else if comparators == nil {
		comparators = Comparators
	}

	if len(modifiers) == 0 {
		return defaultComparator.Matches, nil
	}

	// A valid sequence of modifiers contains at most one comparator; the rest are
	// value modifiers applied (left to right) to the expected value. The comparator
	// may appear at any position - real-world rules write both `windash|contains`
	// and `contains|windash` (pySigma accepts both with the same meaning).
	// If no comparator is specified, the default comparator is used
	var valueModifiers []ValueModifier
	var eventValueModifiers []ValueModifier
	var comparator Comparator
	for _, modifier := range modifiers {
		comparatorModifier := comparators[modifier]
		valueModifier := ValueModifiers[modifier]
		eventValueModifier := EventValueModifiers[modifier]
		switch {
		// Validate correctness
		case comparatorModifier == nil && valueModifier == nil && eventValueModifier == nil:
			return nil, fmt.Errorf("unknown modifier %s", modifier)

		// Build up list of modifiers
		case valueModifier != nil:
			valueModifiers = append(valueModifiers, valueModifier)
		case eventValueModifier != nil:
			eventValueModifiers = append(eventValueModifiers, eventValueModifier)
		case comparatorModifier != nil:
			if comparator != nil {
				return nil, fmt.Errorf("only one comparator modifier is allowed but found a second: %s", modifier)
			}
			if modifier == "re" && reFlags != "" {
				comparator = re{flags: reFlags}
			} else {
				comparator = comparatorModifier
			}
		}
	}
	if comparator == nil {
		comparator = defaultComparator
	}

	return func(actual, expected any) (bool, error) {
		var err error
		for _, modifier := range eventValueModifiers {
			actual, err = modifier.Modify(actual)
			if err != nil {
				return false, err
			}
		}

		// Value modifiers are applied left to right. Most map a single value to a
		// single value, but some (e.g. base64offset, windash) expand one value into
		// several candidate values. We thread a list through the chain so that any
		// expansion is flat-mapped, and the field matches if it matches ANY candidate.
		expectedValues := []any{expected}
		for _, modifier := range valueModifiers {
			var next []any
			for _, value := range expectedValues {
				if multi, ok := modifier.(MultiValueModifier); ok {
					expanded, err := multi.ModifyMulti(value)
					if err != nil {
						return false, err
					}
					next = append(next, expanded...)
				} else {
					modified, err := modifier.Modify(value)
					if err != nil {
						return false, err
					}
					next = append(next, modified)
				}
			}
			expectedValues = next
		}

		for _, value := range expectedValues {
			var matched bool
			if fieldComparator, ok := comparator.(FieldComparator); ok {
				matched, err = fieldComparator.MatchesField(field, actual, value)
			} else {
				matched, err = comparator.Matches(actual, value)
			}
			if err != nil {
				return false, err
			}
			if matched {
				return true, nil
			}
		}
		return false, nil
	}, nil
}

// Comparator defines how the comparison between actual and expected field values is performed (the default is exact string equality).
// For example, the `cidr` modifier uses a check based on the *net.IPNet Contains function
type Comparator interface {
	Matches(actual any, expected any) (bool, error)
}

// FieldComparator is an optional extension to Comparator which also passes the field name
type FieldComparator interface {
	MatchesField(field string, actual any, expected any) (bool, error)
}

type ComparatorFunc func(actual, expected any) (bool, error)

// ValueModifier modifies the expected value before it is passed to the comparator.
// For example, the `base64` modifier converts the expected value to base64.
type ValueModifier interface {
	Modify(value any) (any, error)
}

// MultiValueModifier is an optional extension to ValueModifier for modifiers that
// expand a single value into several candidate values (the field matches if any
// of them match). For example, `base64offset` produces three encodings to cover
// the possible byte alignments of a string embedded in Base64 data, and `windash`
// produces variants with interchangeable command-line dash characters.
type MultiValueModifier interface {
	ValueModifier
	ModifyMulti(value any) ([]any, error)
}

var Comparators = map[string]Comparator{
	"contains":   contains{},
	"endswith":   endswith{},
	"startswith": startswith{},
	"re":         re{},
	"cidr":       cidr{},
	"gt":         gt{},
	"gte":        gte{},
	"lt":         lt{},
	"lte":        lte{},
}

var ComparatorsCaseSensitive = map[string]Comparator{
	"contains":   containsCS{},
	"endswith":   endswithCS{},
	"startswith": startswithCS{},
	"re":         re{},
	"cidr":       cidr{},
	"gt":         gt{},
	"gte":        gte{},
	"lt":         lt{},
	"lte":        lte{},
}

var ValueModifiers = map[string]ValueModifier{
	"base64":       b64{},
	"base64offset": base64offset{},
	"utf16le":      utf16le{},
	"utf16be":      utf16be{},
	"utf16":        utf16WithBOM{},
	"wide":         utf16le{}, // `wide` is a Sigma alias for utf16le
	"windash":      windash{},
}

// EventValueModifiers modify the value in the event before comparison (as opposed to ValueModifiers which modify the value in the rule)
var EventValueModifiers = map[string]ValueModifier{
	// Timestamp component modifiers: parse the event's field value as a timestamp
	// and replace it with the requested component, which the comparator then matches
	// against the rule's numeric value (e.g. `Timestamp|hour: 0`).
	"minute": timestampModifier{tsMinute},
	"hour":   timestampModifier{tsHour},
	"day":    timestampModifier{tsDay},
	"week":   timestampModifier{tsWeek},
	"month":  timestampModifier{tsMonth},
	"year":   timestampModifier{tsYear},
}

type baseComparator struct{}

func (baseComparator) Matches(actual, expected any) (bool, error) {
	switch {
	case actual == nil:
		// special case: "null" should match the case where a field isn't present (and so actual is nil)
		// A missing field matches nothing else (in particular not the `*` wildcard, which requires a value).
		return expected == "null", nil
	default:
		// The Sigma spec defines that by default comparisons are case-insensitive
		// and that unescaped `*`/`?` in plain values are wildcards
		return matchWildcard(CoerceString(actual), CoerceString(expected), false), nil
	}
}

// baseComparatorCased is the case-sensitive equivalent of baseComparator, used
// for the default (equality) comparison when the `cased` modifier is present.
type baseComparatorCased struct{}

func (baseComparatorCased) Matches(actual, expected any) (bool, error) {
	switch {
	case actual == nil:
		return expected == "null", nil
	default:
		return matchWildcard(CoerceString(actual), CoerceString(expected), true), nil
	}
}

// The contains/startswith/endswith comparators add implicit wildcards around the
// rule value (`*X*`, `X*`, `*X` respectively) and, like pySigma, honour any `*`/`?`
// wildcards written inside X. When the value has no wildcards the fast,
// allocation-free fold helpers are used; otherwise the value is matched through the
// shared wildcard engine (anchored regex).

type contains struct{}

func (contains) Matches(actual, expected any) (bool, error) {
	a, e := CoerceString(actual), CoerceString(expected)
	if HasUnescapedWildcard(e) {
		return matchWildcard(a, "*"+e+"*", false), nil
	}
	// The Sigma spec defines that by default comparisons are case-insensitive
	return containsFold(a, e), nil
}

type endswith struct{}

func (endswith) Matches(actual, expected any) (bool, error) {
	a, e := CoerceString(actual), CoerceString(expected)
	if HasUnescapedWildcard(e) {
		return matchWildcard(a, "*"+e, false), nil
	}
	// The Sigma spec defines that by default comparisons are case-insensitive
	return hasSuffixFold(a, e), nil
}

type startswith struct{}

func (startswith) Matches(actual, expected any) (bool, error) {
	a, e := CoerceString(actual), CoerceString(expected)
	if HasUnescapedWildcard(e) {
		return matchWildcard(a, e+"*", false), nil
	}
	// The Sigma spec defines that by default comparisons are case-insensitive
	return hasPrefixFold(a, e), nil
}

// The case-insensitive comparators run once per rule value per event, so the
// obvious strings.ToLower implementation allocates two copies of the field
// value for every single comparison. These helpers compare ASCII (the
// overwhelmingly common case for log values) without allocating, falling back
// to ToLower for non-ASCII input.

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

func lowerByte(b byte) byte {
	if 'A' <= b && b <= 'Z' {
		return b + 'a' - 'A'
	}
	return b
}

func equalFoldASCII(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if lowerByte(a[i]) != lowerByte(b[i]) {
			return false
		}
	}
	return true
}

func containsFold(s, substr string) bool {
	if !isASCII(s) || !isASCII(substr) {
		return strings.Contains(strings.ToLower(s), strings.ToLower(substr))
	}
	if len(substr) == 0 {
		return true
	}
	if len(substr) > len(s) {
		return false
	}
	first := lowerByte(substr[0])
	for i := 0; i+len(substr) <= len(s); i++ {
		if lowerByte(s[i]) == first && equalFoldASCII(s[i:i+len(substr)], substr) {
			return true
		}
	}
	return false
}

func hasPrefixFold(s, prefix string) bool {
	if !isASCII(s) || !isASCII(prefix) {
		return strings.HasPrefix(strings.ToLower(s), strings.ToLower(prefix))
	}
	return len(s) >= len(prefix) && equalFoldASCII(s[:len(prefix)], prefix)
}

func hasSuffixFold(s, suffix string) bool {
	if !isASCII(s) || !isASCII(suffix) {
		return strings.HasSuffix(strings.ToLower(s), strings.ToLower(suffix))
	}
	return len(s) >= len(suffix) && equalFoldASCII(s[len(s)-len(suffix):], suffix)
}

type containsCS struct{}

func (containsCS) Matches(actual, expected any) (bool, error) {
	a, e := CoerceString(actual), CoerceString(expected)
	if HasUnescapedWildcard(e) {
		return matchWildcard(a, "*"+e+"*", true), nil
	}
	return strings.Contains(a, e), nil
}

type endswithCS struct{}

func (endswithCS) Matches(actual, expected any) (bool, error) {
	a, e := CoerceString(actual), CoerceString(expected)
	if HasUnescapedWildcard(e) {
		return matchWildcard(a, "*"+e, true), nil
	}
	return strings.HasSuffix(a, e), nil
}

type startswithCS struct{}

func (startswithCS) Matches(actual, expected any) (bool, error) {
	a, e := CoerceString(actual), CoerceString(expected)
	if HasUnescapedWildcard(e) {
		return matchWildcard(a, e+"*", true), nil
	}
	return strings.HasPrefix(a, e), nil
}

type b64 struct{}

func (b64) Modify(value any) (any, error) {
	return base64.StdEncoding.EncodeToString([]byte(CoerceString(value))), nil
}

// encodeUTF16 encodes s as UTF-16 with the given byte order, optionally prefixed
// with a byte-order mark. The result is returned as a string holding the raw
// bytes so it can be threaded through the modifier chain (typically into base64).
func encodeUTF16(s string, order binary.ByteOrder, bom bool) string {
	units := utf16.Encode([]rune(s))
	buf := make([]byte, 0, len(units)*2+2)
	put := func(u uint16) {
		var b [2]byte
		order.PutUint16(b[:], u)
		buf = append(buf, b[0], b[1])
	}
	if bom {
		put(0xFEFF)
	}
	for _, u := range units {
		put(u)
	}
	return string(buf)
}

// utf16le implements the `utf16le` modifier (also registered as the `wide` alias).
type utf16le struct{}

func (utf16le) Modify(value any) (any, error) {
	return encodeUTF16(CoerceString(value), binary.LittleEndian, false), nil
}

// utf16be implements the `utf16be` modifier.
type utf16be struct{}

func (utf16be) Modify(value any) (any, error) {
	return encodeUTF16(CoerceString(value), binary.BigEndian, false), nil
}

// utf16WithBOM implements the `utf16` modifier which, like Python's 'utf-16'
// codec used by pySigma, emits a little-endian byte-order mark followed by
// little-endian UTF-16.
type utf16WithBOM struct{}

func (utf16WithBOM) Modify(value any) (any, error) {
	return encodeUTF16(CoerceString(value), binary.LittleEndian, true), nil
}

// base64offset implements the `base64offset` modifier. A string embedded in a
// larger blob of Base64 data can begin at one of three byte alignments, each of
// which produces a different Base64 substring. This emits all three variants
// (using the same start/end offset table as pySigma) so that a `contains` match
// finds the string regardless of its position in the encoded data.
type base64offset struct{}

var (
	base64offsetStart   = [3]int{0, 2, 3}
	base64offsetEndTrim = [3]int{0, 3, 2}
)

func (b base64offset) Modify(value any) (any, error) {
	// When used as a single-value modifier, fall back to the offset-0 encoding.
	expanded, err := b.ModifyMulti(value)
	if err != nil {
		return nil, err
	}
	return expanded[0], nil
}

func (base64offset) ModifyMulti(value any) ([]any, error) {
	raw := []byte(CoerceString(value))
	out := make([]any, 3)
	for i := 0; i < 3; i++ {
		prefixed := append(bytes.Repeat([]byte{' '}, i), raw...)
		encoded := base64.StdEncoding.EncodeToString(prefixed)
		if start := base64offsetStart[i]; start < len(encoded) {
			encoded = encoded[start:]
		} else {
			encoded = ""
		}
		// The number of trailing characters affected by the (unknown) bytes that
		// follow the value depends on how many bytes spill into the final base64
		// group, i.e. on (len(value)+i) mod 3 - not on the offset i itself.
		if trim := base64offsetEndTrim[(len(raw)+i)%3]; trim < len(encoded) {
			encoded = encoded[:len(encoded)-trim]
		} else {
			encoded = ""
		}
		out[i] = encoded
	}
	return out, nil
}

// windash implements the `windash` modifier, expanding a value into variants where
// each command-line dash is swapped for an interchangeable equivalent (hyphen,
// forward slash, en dash, em dash, horizontal bar). This catches argument spoofing
// where e.g. `-foo` is written as `/foo` or with a Unicode dash.
//
// Like pySigma's SigmaWindowsDashModifier, only `-` and `/` written at an
// argument-leading position are expanded: the trigger is `\B[-/]\b`, i.e. a dash
// that is not preceded by a word boundary but is followed by one (e.g. ` -foo`,
// `/foo`). Hyphens inside words (`foo-bar`) are left untouched, so the expansion
// doesn't over-generate variants and match more than pySigma would.
type windash struct{}

// windashChars is the set each trigger position is expanded into.
var windashChars = []rune{'-', '/', '–', '—', '―'}

// windashTrigger matches the dashes pySigma expands (`\B[-/]\b`).
var windashTrigger = regexp.MustCompile(`\B[-/]\b`)

// windashMaxPositions bounds the cartesian product (len(windashChars)^n). Rule
// values almost always contain a single dash; the cap only guards against
// pathological rule values and truncates extra dash positions if exceeded.
const windashMaxPositions = 6

func (w windash) Modify(value any) (any, error) {
	expanded, err := w.ModifyMulti(value)
	if err != nil {
		return nil, err
	}
	return expanded[0], nil
}

func (windash) ModifyMulti(value any) ([]any, error) {
	s := CoerceString(value)
	// Each match is a single ASCII byte (`-` or `/`); byte offsets are safe to slice.
	positions := windashTrigger.FindAllStringIndex(s, -1)
	if len(positions) == 0 {
		return []any{s}, nil
	}
	if len(positions) > windashMaxPositions {
		positions = positions[:windashMaxPositions]
	}

	total := 1
	for range positions {
		total *= len(windashChars)
	}
	variants := make([]any, 0, total)
	for combo := 0; combo < total; combo++ {
		var buf strings.Builder
		buf.Grow(len(s))
		prev := 0
		n := combo
		for _, pos := range positions {
			buf.WriteString(s[prev:pos[0]])
			buf.WriteRune(windashChars[n%len(windashChars)])
			n /= len(windashChars)
			prev = pos[1]
		}
		buf.WriteString(s[prev:])
		variants = append(variants, buf.String())
	}
	return variants, nil
}

// reFlagChar maps a Sigma regex flag sub-modifier (short or long form, as accepted
// by pySigma) to the single inline-flag character Go's regexp uses.
func reFlagChar(modifier string) (string, bool) {
	switch modifier {
	case "i", "ignorecase":
		return "i", true
	case "m", "multiline":
		return "m", true
	case "s", "dotall":
		return "s", true
	default:
		return "", false
	}
}

// re implements the `re` comparator. flags holds any Sigma regex flag
// sub-modifiers (a combination of i, m, s from re|i, re|m, re|s, or their long
// forms re|ignorecase, re|multiline, re|dotall) which are translated to Go's
// inline regex flags, e.g. flags "im" -> "(?im)" prefix.
type re struct {
	flags string
}

// compiledRegexps caches compiled patterns: Matches is called once per event so
// compiling inline would dominate evaluation cost. Patterns come from rules so
// the cardinality is bounded by the loaded ruleset.
var compiledRegexps sync.Map // map[string]*regexp.Regexp

func CompileRegex(pattern string) (*regexp.Regexp, error) {
	if cached, ok := compiledRegexps.Load(pattern); ok {
		return cached.(*regexp.Regexp), nil
	}
	compiled, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	compiledRegexps.Store(pattern, compiled)
	return compiled, nil
}

func (r re) Matches(actual any, expected any) (bool, error) {
	pattern := CoerceString(expected)
	if r.flags != "" {
		pattern = "(?" + r.flags + ")" + pattern
	}
	compiled, err := CompileRegex(pattern)
	if err != nil {
		return false, err
	}

	return compiled.MatchString(CoerceString(actual)), nil
}

type cidr struct{}

func (cidr) Matches(actual any, expected any) (bool, error) {
	_, cidr, err := net.ParseCIDR(CoerceString(expected))
	if err != nil {
		return false, err
	}

	ip := net.ParseIP(CoerceString(actual))
	return cidr.Contains(ip), nil
}

type gt struct{}

func (gt) Matches(actual any, expected any) (bool, error) {
	gt, _, _, _, err := compareNumeric(actual, expected)
	return gt, err
}

type gte struct{}

func (gte) Matches(actual any, expected any) (bool, error) {
	_, gte, _, _, err := compareNumeric(actual, expected)
	return gte, err
}

type lt struct{}

func (lt) Matches(actual any, expected any) (bool, error) {
	_, _, lt, _, err := compareNumeric(actual, expected)
	return lt, err
}

type lte struct{}

func (lte) Matches(actual any, expected any) (bool, error) {
	_, _, _, lte, err := compareNumeric(actual, expected)
	return lte, err
}

// timestampPart identifies which component a timestamp modifier extracts.
type timestampPart int

const (
	tsMinute timestampPart = iota
	tsHour
	tsDay
	tsWeek
	tsMonth
	tsYear
)

// timestampModifier implements the `minute`/`hour`/`day`/`week`/`month`/`year`
// modifiers (pySigma's SigmaTimestamp*Modifier). It is an EventValueModifier: it
// parses the event field value as a timestamp and returns the requested component
// as an int, so the comparator matches it against the rule's numeric value. Like
// pySigma, `week` is the ISO week of the year.
type timestampModifier struct{ part timestampPart }

// timestampLayouts are tried in order when parsing a string field value.
var timestampLayouts = []string{
	time.RFC3339Nano,
	time.RFC3339,
	"2006-01-02T15:04:05",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02",
}

func (m timestampModifier) Modify(value any) (any, error) {
	t, err := coerceTime(value)
	if err != nil {
		return nil, err
	}
	switch m.part {
	case tsMinute:
		return t.Minute(), nil
	case tsHour:
		return t.Hour(), nil
	case tsDay:
		return t.Day(), nil
	case tsWeek:
		_, week := t.ISOWeek()
		return week, nil
	case tsMonth:
		return int(t.Month()), nil
	case tsYear:
		return t.Year(), nil
	default:
		return nil, fmt.Errorf("unknown timestamp part %d", m.part)
	}
}

// coerceTime parses an event field value into a time.Time. Numeric values are
// treated as Unix seconds. An unparseable value yields an error, which the caller
// treats as a non-match (see matcherMatchesValues).
func coerceTime(value any) (time.Time, error) {
	switch v := value.(type) {
	case time.Time:
		return v, nil
	case int:
		return time.Unix(int64(v), 0).UTC(), nil
	case int64:
		return time.Unix(v, 0).UTC(), nil
	case float64:
		sec := int64(v)
		return time.Unix(sec, int64((v-float64(sec))*1e9)).UTC(), nil
	}
	s := CoerceString(value)
	for _, layout := range timestampLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("cannot parse %q as timestamp", s)
}

func CoerceString(v interface{}) string {
	switch vv := v.(type) {
	case string:
		return vv
	case []byte:
		return string(vv)
	default:
		return fmt.Sprint(vv)
	}
}

// coerceNumeric makes both operands into the widest possible number of the same type
func coerceNumeric(left, right interface{}) (interface{}, interface{}, error) {
	// Check for nil interface, otherwise the function panics
	if left == nil || right == nil {
		return nil, nil, fmt.Errorf("cannot coerce %T and %T to numeric", left, right)
	}
	leftV := reflect.ValueOf(left)
	leftType := reflect.ValueOf(left).Type()
	rightV := reflect.ValueOf(right)
	rightType := reflect.ValueOf(right).Type()

	switch {
	// Both integers or both floats? Return directly
	case leftType.Kind() == reflect.Int && rightType.Kind() == reflect.Int:
		fallthrough
	case leftType.Kind() == reflect.Float64 && rightType.Kind() == reflect.Float64:
		return left, right, nil

	// Mixed integer, float? Return two floats
	case leftType.Kind() == reflect.Int && rightType.Kind() == reflect.Float64:
		fallthrough
	case leftType.Kind() == reflect.Float64 && rightType.Kind() == reflect.Int:
		floatType := reflect.TypeOf(float64(0))
		return leftV.Convert(floatType).Interface(), rightV.Convert(floatType).Interface(), nil

	// One or more strings? Parse and recurse.
	// We use `yaml.Unmarshal` to parse the string because it's a cheat's way of parsing either an integer or a float
	case leftType.Kind() == reflect.String:
		var leftParsed interface{}
		if err := yaml.Unmarshal([]byte(left.(string)), &leftParsed); err != nil {
			return nil, nil, err
		}
		//Check the parsed type is the correct one, otherwise we get a stack overflow
		if reflect.TypeOf(leftParsed).Kind() != reflect.Float64 && reflect.TypeOf(leftParsed).Kind() != reflect.Int {
			return nil, nil, fmt.Errorf("cannot coerce %T and %T to numeric", left, right)
		}
		return coerceNumeric(leftParsed, right)
	case rightType.Kind() == reflect.String:
		var rightParsed interface{}
		if err := yaml.Unmarshal([]byte(right.(string)), &rightParsed); err != nil {
			return nil, nil, err
		}
		//Check the parsed type is the correct one, otherwise we get a stack overflow
		if reflect.TypeOf(rightParsed).Kind() != reflect.Float64 && reflect.TypeOf(rightParsed).Kind() != reflect.Int {
			return nil, nil, fmt.Errorf("cannot coerce %T and %T to numeric", left, right)
		}
		return coerceNumeric(left, rightParsed)

	default:
		return nil, nil, fmt.Errorf("cannot coerce %T and %T to numeric", left, right)
	}
}

func compareNumeric(left, right interface{}) (gt, gte, lt, lte bool, err error) {
	left, right, err = coerceNumeric(left, right)
	if err != nil {
		return
	}

	switch left.(type) {
	case int:
		left := left.(int)
		right := right.(int)
		return left > right, left >= right, left < right, left <= right, nil
	case float64:
		left := left.(float64)
		right := right.(float64)
		return left > right, left >= right, left < right, left <= right, nil
	default:
		err = fmt.Errorf("internal, please report! coerceNumeric returned unexpected types %T and %T", left, right)
		return
	}
}
