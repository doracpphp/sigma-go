package evaluator

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/PaesslerAG/jsonpath"
	"github.com/doracpphp/sigma-go"
	"github.com/doracpphp/sigma-go/evaluator/modifiers"
	"path"
	"reflect"
	"regexp"
	"strings"
)

func (rule RuleEvaluator) evaluateSearchExpression(search sigma.SearchExpr, searchResults func(string) bool) bool {
	switch s := search.(type) {
	case sigma.And:
		for _, node := range s {
			if !rule.evaluateSearchExpression(node, searchResults) {
				return false
			}
		}
		return true

	case sigma.Or:
		for _, node := range s {
			if rule.evaluateSearchExpression(node, searchResults) {
				return true
			}
		}
		return false

	case sigma.Not:
		return !rule.evaluateSearchExpression(s.Expr, searchResults)

	case sigma.SearchIdentifier:
		// If `s.Name` is not defined, this is always false
		return searchResults(s.Name)

	case sigma.OneOfThem:
		for name := range rule.Detection.Searches {
			if rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, searchResults) {
				return true
			}
		}
		return false

	case sigma.OneOfPattern:
		for name := range rule.Detection.Searches {
			// it's not possible for this call to error because the search expression parser won't allow this to contain invalid expressions
			matchesPattern, _ := path.Match(s.Pattern, name)
			if !matchesPattern {
				continue
			}
			if rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, searchResults) {
				return true
			}
		}
		return false

	case sigma.AllOfThem:
		for name := range rule.Detection.Searches {
			if !rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, searchResults) {
				return false
			}
		}
		return true

	case sigma.AllOfPattern:
		for name := range rule.Detection.Searches {
			// it's not possible for this call to error because the search expression parser won't allow this to contain invalid expressions
			matchesPattern, _ := path.Match(s.Pattern, name)
			if !matchesPattern {
				continue
			}
			if !rule.evaluateSearchExpression(sigma.SearchIdentifier{Name: name}, searchResults) {
				return false
			}
		}
		return true
	}
	panic(fmt.Sprintf("unhandled node type %T", search))
}

func (rule RuleEvaluator) evaluateSearch(ctx context.Context, search sigma.Search, event Event, comparators map[string]modifiers.Comparator) (bool, error) {
	if len(search.Keywords) > 0 {
		// Keywords are a valueless list of strings matched against the whole event
		// (full-text search). The list is OR-ed by default.
		return rule.matchKeywords(search.Keywords, event), nil
	}

	if len(search.EventMatchers) == 0 {
		// degenerate case (but common for logsource conditions)
		return true, nil
	}

	// A Search is a series of EventMatchers (usually one)
	// Each EventMatchers is a series of "does this field match this value" conditions
	// all fields need to match for an EventMatcher to match, but only one EventMatcher needs to match for the Search to evaluate to true
eventMatcher:
	for _, eventMatcher := range search.EventMatchers {
		for _, fieldMatcher := range eventMatcher {
			// A field matcher can specify multiple values to match against
			// either the field should match all of these values or it should match any of them
			allValuesMustMatch := false
			fieldModifiers := fieldMatcher.Modifiers
			if len(fieldMatcher.Modifiers) > 0 && fieldModifiers[len(fieldModifiers)-1] == "all" {
				allValuesMustMatch = true
				fieldModifiers = fieldModifiers[:len(fieldModifiers)-1]
			}

			// `exists`, `fieldref` and `neq` are handled here rather than inside the
			// comparator: `exists`/`fieldref` need access to the event itself, and `neq`
			// negates the whole field match. Strip them out of the modifier list first.
			useExists := false
			useFieldRef := false
			negate := false
			var passModifiers []string
			for _, m := range fieldModifiers {
				switch m {
				case "exists":
					useExists = true
				case "fieldref":
					useFieldRef = true
				case "neq":
					// `neq` is pySigma's SigmaNegateModifier: it negates the match of this
					// detection item (NOT match). It applies on top of whatever comparator
					// and value-linking (any/all) the rest of the modifiers select.
					negate = true
				case "expand":
					// `expand` marks the value as a `%placeholder%` to be expanded;
					// getMatcherValues already expands whole-value placeholders, so the
					// modifier itself is a no-op here.
				default:
					passModifiers = append(passModifiers, m)
				}
			}
			fieldModifiers = passModifiers

			matcherValues, err := rule.getMatcherValues(ctx, fieldMatcher)
			if err != nil {
				return false, err
			}

			// `exists` checks field presence against a boolean and ignores any comparator.
			if useExists {
				matched := rule.matcherMatchesExists(fieldMatcher.Field, matcherValues, allValuesMustMatch, event)
				// The field passes unless the (possibly negated) result is false.
				if matched == negate {
					continue eventMatcher
				}
				continue
			}

			// field matchers can specify modifiers (FieldName|modifier1|modifier2) which change the matching behaviour
			var comparator modifiers.ComparatorFunc
			comparator, err = modifiers.GetComparator(fieldMatcher.Field, comparators, fieldModifiers...)
			if err != nil {
				return false, err
			}

			// `fieldref` resolves each "value" as the name of another field and compares
			// against that field's value in the event instead of a literal.
			if useFieldRef {
				matcherValues, err = rule.resolveFieldRefValues(matcherValues, event)
				if err != nil {
					return false, err
				}
			}

			values, err := rule.GetFieldValuesFromEvent(fieldMatcher.Field, event)
			if err != nil {
				return false, err
			}
			matched := rule.matcherMatchesValues(matcherValues, comparator, allValuesMustMatch, values)
			// `neq` negates the field match (pySigma's SigmaNegateModifier). The field
			// passes when matched != negate; otherwise the overall matcher fails and we
			// try the next EventMatcher.
			if matched == negate {
				continue eventMatcher
			}
		}

		// all fields matched!
		return true, nil
	}

	// None of the event matchers explicitly matched
	return false, nil
}

// matchKeywords implements Sigma keyword (full-text) search: a list of strings
// matched against every field value in the event. The keywords are OR-ed, and a
// single keyword matches if it is found (case-insensitively by default, with `*`
// and `?` wildcards) within any field value.
func (rule RuleEvaluator) matchKeywords(keywords []string, event Event) bool {
	values := allEventValues(event)
	for _, keyword := range keywords {
		for _, value := range values {
			if keywordMatches(keyword, value, rule.caseSensitive) {
				return true
			}
		}
	}
	return false
}

// allEventValues returns the string form of every top-level field value in the event.
func allEventValues(event Event) []string {
	switch evt := event.(type) {
	case map[string]string:
		out := make([]string, 0, len(evt))
		for _, v := range evt {
			out = append(out, v)
		}
		return out
	case map[string]interface{}:
		out := make([]string, 0, len(evt))
		for _, v := range evt {
			out = append(out, modifiers.CoerceString(v))
		}
		return out
	default:
		return nil
	}
}

func keywordMatches(keyword, value string, caseSensitive bool) bool {
	if strings.ContainsAny(keyword, "*?") {
		re, err := keywordRegexp(keyword, caseSensitive)
		if err != nil {
			return false
		}
		return re.MatchString(value)
	}
	if caseSensitive {
		return strings.Contains(value, keyword)
	}
	return strings.Contains(strings.ToLower(value), strings.ToLower(keyword))
}

// keywordRegexp converts a keyword containing `*`/`?` wildcards into an unanchored
// regexp (keyword search has "contains" semantics).
func keywordRegexp(keyword string, caseSensitive bool) (*regexp.Regexp, error) {
	var b strings.Builder
	if !caseSensitive {
		b.WriteString("(?i)")
	}
	for _, r := range keyword {
		switch r {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(r)))
		}
	}
	return regexp.Compile(b.String())
}

// placeholderToken matches a single `%name%` placeholder. Names are restricted to
// identifier-like characters so that stray `%` (e.g. URL-encoded `%20`) doesn't
// accidentally look like a placeholder.
var placeholderToken = regexp.MustCompile(`%[A-Za-z0-9_.-]+%`)

func (rule *RuleEvaluator) getMatcherValues(ctx context.Context, matcher sigma.FieldMatcher) ([]string, error) {
	hasExpand := false
	for _, m := range matcher.Modifiers {
		if m == "expand" {
			hasExpand = true
			break
		}
	}

	matcherValues := []string{}
	for _, abstractValue := range matcher.Values {
		value := ""

		switch abstractValue := abstractValue.(type) {
		case nil:
			// `Field: null` matches absent fields. The comparators represent this
			// with the "null" sentinel (see baseComparator).
			value = "null"
		case string:
			value = abstractValue
		case int, float32, float64, bool:
			value = fmt.Sprintf("%v", abstractValue)
		default:
			return nil, fmt.Errorf("expected scalar field matching value got: %v (%T)", abstractValue, abstractValue)
		}

		switch {
		case strings.HasPrefix(value, "%") && strings.HasSuffix(value, "%"):
			// The whole value is a placeholder; expand it to its values.
			if rule.expandPlaceholder == nil {
				return nil, fmt.Errorf("can't expand %s, no placeholder expander function defined", value)
			}
			placeholderValues, err := rule.expandPlaceholder(ctx, value)
			if err != nil {
				return nil, fmt.Errorf("failed to expand placeholder: %w", err)
			}
			matcherValues = append(matcherValues, placeholderValues...)
		case hasExpand && placeholderToken.MatchString(value):
			// A `%name%` placeholder embedded inside a larger value (e.g.
			// `C:\Users\%user%\file`). Expand each placeholder and emit the cartesian
			// product of the surrounding literal text with the expansion values.
			expanded, err := rule.expandEmbeddedPlaceholders(ctx, value)
			if err != nil {
				return nil, err
			}
			matcherValues = append(matcherValues, expanded...)
		default:
			matcherValues = append(matcherValues, value)
		}
	}
	return matcherValues, nil
}

// expandEmbeddedPlaceholders replaces every `%name%` placeholder in value with its
// expansion values, returning the cartesian product of the resulting strings. A
// placeholder that expands to no values yields no candidates (the value matches
// nothing), mirroring the whole-value placeholder behaviour.
func (rule *RuleEvaluator) expandEmbeddedPlaceholders(ctx context.Context, value string) ([]string, error) {
	if rule.expandPlaceholder == nil {
		return nil, fmt.Errorf("can't expand %s, no placeholder expander function defined", value)
	}

	results := []string{""}
	last := 0
	for _, loc := range placeholderToken.FindAllStringIndex(value, -1) {
		literal := value[last:loc[0]]
		token := value[loc[0]:loc[1]]
		last = loc[1]

		placeholderValues, err := rule.expandPlaceholder(ctx, token)
		if err != nil {
			return nil, fmt.Errorf("failed to expand placeholder: %w", err)
		}

		next := make([]string, 0, len(results)*len(placeholderValues))
		for _, prefix := range results {
			for _, pv := range placeholderValues {
				next = append(next, prefix+literal+pv)
			}
		}
		results = next
	}

	// Append any trailing literal after the final placeholder.
	if tail := value[last:]; tail != "" {
		for i := range results {
			results[i] += tail
		}
	}
	return results, nil
}

func (rule *RuleEvaluator) GetFieldValuesFromEvent(field string, event Event) ([]interface{}, error) {
	// First collect this list of event values we're matching against
	var actualValues []interface{}
	if len(rule.fieldmappings[field]) == 0 {
		// No FieldMapping exists so use the name directly from the rule
		actualValues = []interface{}{eventValue(event, field)}
	} else {
		// FieldMapping does exist so check each of the possible mapped names instead of the name from the rule
		for _, mapping := range rule.fieldmappings[field] {
			var v interface{}
			var err error

			switch {
			case strings.HasPrefix(mapping, "$.") || strings.HasPrefix(mapping, "$["):
				v, err = evaluateJSONPath(mapping, event)
			default:
				v = eventValue(event, mapping)
			}
			if err != nil {
				return nil, err
			}

			actualValues = append(actualValues, toGenericSlice(v)...)
		}
	}

	return actualValues, nil
}

func (rule *RuleEvaluator) matcherMatchesValues(matcherValues []string, comparator modifiers.ComparatorFunc, allValuesMustMatch bool, actualValues []interface{}) bool {
	matched := allValuesMustMatch
	for _, expectedValue := range matcherValues {
		valueMatchedEvent := false
		// There are multiple possible event fields that each expected value needs to be compared against
		for _, actualValue := range actualValues {
			comparatorMatched, err := comparator(actualValue, expectedValue)
			if err != nil {
				// todo
			}
			if comparatorMatched {
				valueMatchedEvent = true
				break
			}
		}

		if allValuesMustMatch {
			matched = matched && valueMatchedEvent
		} else {
			matched = matched || valueMatchedEvent
		}
	}
	return matched
}

// matcherMatchesExists implements the `exists` modifier: it compares whether the
// field is present in the event against the boolean rule value(s) ("true"/"false").
func (rule *RuleEvaluator) matcherMatchesExists(field string, matcherValues []string, allValuesMustMatch bool, event Event) bool {
	present := rule.fieldExistsInEvent(field, event)
	matched := allValuesMustMatch
	for _, expectedValue := range matcherValues {
		want := strings.EqualFold(expectedValue, "true")
		valueMatched := present == want
		if allValuesMustMatch {
			matched = matched && valueMatched
		} else {
			matched = matched || valueMatched
		}
	}
	return matched
}

// resolveFieldRefValues implements the `fieldref` modifier: each matcher value is
// the name of another field, which is resolved to that field's value(s) in the
// event. Missing referenced fields contribute no values (so they don't match).
func (rule *RuleEvaluator) resolveFieldRefValues(fieldNames []string, event Event) ([]string, error) {
	var resolved []string
	for _, name := range fieldNames {
		values, err := rule.GetFieldValuesFromEvent(name, event)
		if err != nil {
			return nil, err
		}
		for _, v := range values {
			if v == nil {
				continue
			}
			resolved = append(resolved, modifiers.CoerceString(v))
		}
	}
	return resolved, nil
}

// fieldExistsInEvent reports whether the (possibly field-mapped) rule field is
// present in the event.
func (rule *RuleEvaluator) fieldExistsInEvent(field string, event Event) bool {
	mappings := rule.fieldmappings[field]
	if len(mappings) == 0 {
		return eventKeyExists(event, field)
	}
	for _, mapping := range mappings {
		switch {
		case strings.HasPrefix(mapping, "$.") || strings.HasPrefix(mapping, "$["):
			if v, err := evaluateJSONPath(mapping, event); err == nil && v != nil {
				return true
			}
		default:
			if eventKeyExists(event, mapping) {
				return true
			}
		}
	}
	return false
}

func eventKeyExists(e Event, key string) bool {
	switch evt := e.(type) {
	case map[string]string:
		_, ok := evt[key]
		return ok
	case map[string]interface{}:
		_, ok := evt[key]
		return ok
	default:
		return false
	}
}

// This is a hack because none of the JSONPath libraries expose the parsed AST :(
// Matches JSONPaths with either a $.fieldname or $["fieldname"] prefix and extracts 'fieldname'
var firstJSONPathField = regexp.MustCompile(`^\$(?:[.]|\[")([a-zA-Z0-9_\-]+)(?:"])?`)

func evaluateJSONPath(expr string, event Event) (interface{}, error) {
	// First, just try to evaluate the JSONPath expression directly
	value, err := jsonpath.Get(expr, event)
	switch {
	case err == nil:
		// Got no error so return the value directly
		return value, nil
	case strings.HasPrefix(err.Error(), "unknown key "):
		// This means we tried to access a nested field that wasn't present in the event.
		// This is an expected situation which just results in returning no value (the same as if we were trying to access a top level field that didn't exist)
		return nil, nil
	case strings.HasPrefix(err.Error(), "unsupported value type"):
		// handled below
	default:
		return nil, err
	}

	// Got an error: "unsupported value type X for select, expected map[string]interface{} or []interface{}"
	// This means we tried to access a nested field that hasn't yet been unmarshalled.
	// We try to fix this by finding the top-level field being selected and attempting to unmarshal it.
	// This is best effort and only works for top-level fields.
	// A longer term solution would be to either build this into the JSONPath library directly or remove this feature and let the user do it.

	jsonPathField := firstJSONPathField.FindStringSubmatch(expr)
	if jsonPathField == nil {
		return nil, fmt.Errorf("couldn't parse JSONPath expression")
	}

	var subValue interface{}
	switch e := event.(type) {
	case map[string]string:
		json.Unmarshal([]byte(e[jsonPathField[1]]), &subValue)
	case map[string]interface{}:
		switch sub := e[jsonPathField[1]].(type) {
		case string:
			json.Unmarshal([]byte(sub), &subValue)
		case []byte:
			json.Unmarshal(sub, &subValue)
		default:
			// Oh well, don't try to unmarshal the nested field
			value, _ := jsonpath.Get(expr, event)
			return value, nil
		}
	}

	value, _ = jsonpath.Get(expr, map[string]interface{}{
		jsonPathField[1]: subValue,
	})
	return value, nil
}

func toGenericSlice(v interface{}) []interface{} {
	rv := reflect.ValueOf(v)

	// if this isn't a slice, then return a slice containing the
	// original value
	if rv.Kind() != reflect.Slice {
		return []interface{}{v}
	}

	out := make([]interface{}, 0, rv.Len())
	for i := 0; i < rv.Len(); i++ {
		out = append(out, rv.Index(i).Interface())
	}

	return out
}
