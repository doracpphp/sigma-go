package evaluator

import (
	"context"
	aho_corasick "github.com/BobuSumisu/aho-corasick"
	"github.com/doracpphp/sigma-go"
	"github.com/doracpphp/sigma-go/evaluator/modifiers"
	"regexp"
	"strings"
	"sync"
	"unsafe"
)

// ForRules compiles a set of rule evaluators which are evaluated together allowing for use of
// more efficient string matching algorithms
func ForRules(rules []sigma.Rule, options ...Option) RuleEvaluatorBundle {
	if len(rules) == 0 {
		return RuleEvaluatorBundle{}
	}

	bundle := RuleEvaluatorBundle{
		ahocorasick: map[string]ahocorasickSearcher{},
	}

	values := map[string][]string{}

	for _, rule := range rules {
		e := ForRule(rule, options...)
		bundle.evaluators = append(bundle.evaluators, e)
		bundle.caseSensitive = e.caseSensitive

		for _, search := range rule.Detection.Searches {
			for _, matcher := range search.EventMatchers {
				for _, fieldMatcher := range matcher {
					contains := false
					regex := false
					for _, modifier := range fieldMatcher.Modifiers {
						if modifier == "contains" {
							contains = true
						}
						if modifier == "re" {
							regex = true
						}
					}
					switch {
					case contains: // add all values to the needle set
						for _, value := range fieldMatcher.Values {
							if value == nil {
								continue
							}
							// Expand any value modifiers (windash, base64offset, ...) so
							// their candidate strings are in the trie too - the comparator
							// looks up the expanded value at match time, not the raw one.
							expanded, err := modifiers.ExpandValueModifiers(value, fieldMatcher.Modifiers)
							if err != nil {
								continue
							}
							for _, ev := range expanded {
								stringValue := modifiers.CoerceString(ev)
								// Wildcard values aren't literal substrings; they're matched
								// via the fallback comparator, so they don't belong in the trie.
								if modifiers.HasUnescapedWildcard(stringValue) {
									continue
								}
								// Resolve escapes (\*, \?, \\) so the trie holds the literal
								// substring the comparator searches for.
								stringValue = modifiers.UnescapeValue(stringValue)
								if !bundle.caseSensitive {
									stringValue = strings.ToLower(stringValue)
								}
								values[fieldMatcher.Field] = append(values[fieldMatcher.Field], stringValue)
							}
						}
					case regex: // get "necessary" substrings and add to the needle set
						for _, value := range fieldMatcher.Values {
							ss, caseInsensitive, _ := regexStrings(modifiers.CoerceString(value)) // todo: benchmark this, should save the result?
							for _, s := range ss {
								if caseInsensitive {
									s = strings.ToLower(s)
								}
								values[fieldMatcher.Field] = append(values[fieldMatcher.Field], s)
							}
						}
					}

				}
			}
		}
	}

	for field, fieldValues := range values {
		patterns := map[string]bool{}
		for _, v := range fieldValues {
			patterns[v] = true
		}
		bundle.ahocorasick[field] = ahocorasickSearcher{
			Trie:     aho_corasick.NewTrieBuilder().AddStrings(fieldValues).Build(),
			patterns: patterns,
		}
	}
	return bundle
}

type RuleEvaluatorBundle struct {
	ahocorasick   map[string]ahocorasickSearcher
	evaluators    []*RuleEvaluator
	caseSensitive bool
}

type ahocorasickSearcher struct {
	*aho_corasick.Trie
	// patterns is the set of needles the trie was built from. A needle outside
	// this set can never be found by the trie, so the comparator falls back to a
	// plain comparison for it (e.g. placeholder- or fieldref-derived values that
	// only exist at match time).
	patterns map[string]bool
}

// resultsKey identifies one cached trie scan: the field, the identity of the
// scanned string and whether the scan was case-sensitive. Case sensitivity must
// be part of the key because a case-insensitive scan lowercases the haystack
// and therefore produces a different match set than a case-sensitive one.
type resultsKey struct {
	field         string
	data          *byte
	caseSensitive bool
}

func (a *ahocorasickContains) getResults(field, s string, caseSensitive bool) map[string]bool {
	as, ok := a.matchers[field]
	if !ok || as.Trie == nil {
		return nil
	}
	key := resultsKey{field, unsafe.StringData(s), caseSensitive} // using the underlying []byte pointer means we only compute results once per interned string
	if result, ok := a.results[key]; ok {
		return result
	}

	// haven't already computed this
	if !caseSensitive {
		s = strings.ToLower(s)
	}
	results := map[string]bool{}
	a.results[key] = results
	for _, match := range as.MatchString(s) {
		results[match.MatchString()] = true
	}
	return results
}

type RuleResult struct {
	Result
	sigma.Rule
}

func (bundle RuleEvaluatorBundle) Matches(ctx context.Context, event Event) ([]RuleResult, error) {
	if len(bundle.evaluators) == 0 {
		return nil, nil
	}

	// copy the current rule comparators
	comparators := map[string]modifiers.Comparator{}
	for name, comparator := range bundle.evaluators[0].comparators {
		comparators[name] = comparator
	}

	// override the contains comparator to use our custom one. The embedded
	// Comparator is the standard contains comparator, used as a fallback for
	// values that can't be looked up in the Aho-Corasick trie (wildcards, or
	// values derived at match time such as placeholder/fieldref expansions).
	fallback := modifiers.Comparators["contains"]
	if bundle.caseSensitive {
		fallback = modifiers.ComparatorsCaseSensitive["contains"]
	}
	contains := &ahocorasickContains{
		Comparator:    fallback,
		matchers:      bundle.ahocorasick,
		caseSensitive: bundle.caseSensitive,
		results:       map[resultsKey]map[string]bool{},
	}
	comparators["contains"] = contains
	comparators["re"] = &ahocorasickRe{
		contains,
	}

	ruleresults := []RuleResult{}
	errs := []error{}
	for _, rule := range bundle.evaluators {
		result, err := rule.matches(ctx, event, comparators)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ruleresults = append(ruleresults, RuleResult{
			Result: result,
			Rule:   rule.Rule,
		})
	}
	return ruleresults, nil
}

type ahocorasickContains struct {
	caseSensitive bool
	modifiers.Comparator
	matchers map[string]ahocorasickSearcher
	results  map[resultsKey]map[string]bool
}

func (a *ahocorasickContains) MatchesField(field string, actual any, expected any) (bool, error) {
	if actual == nil {
		// An absent field has no value to contain anything, so it never matches
		// (mirrors the standard contains comparator).
		return false, nil
	}
	if expected == "" {
		// compatability with old |contains behaviour
		// possibly a bug?
		return true, nil
	}

	needle := modifiers.CoerceString(expected)

	// A `contains` value with wildcards (e.g. `foo*bar`) isn't a literal substring
	// so it can't be looked up in the Aho-Corasick trie. Defer to the standard
	// comparator, which matches it through the wildcard engine. These are rare, so
	// the per-event regex cost is acceptable.
	if modifiers.HasUnescapedWildcard(needle) {
		return a.Comparator.Matches(actual, expected)
	}

	// The trie was built from unescaped (and, in case-insensitive mode, lowercased)
	// rule values; canonicalise the needle the same way before looking it up.
	needle = modifiers.UnescapeValue(needle)
	if !a.caseSensitive {
		needle = strings.ToLower(needle)
	}

	// A needle the trie wasn't built with (a placeholder or fieldref value that
	// only exists at match time, or a field whose values were all skipped at build
	// time) can never be found by the trie; match it with the standard comparator.
	searcher, ok := a.matchers[field]
	if !ok || searcher.Trie == nil || !searcher.patterns[needle] {
		return a.Comparator.Matches(actual, expected)
	}

	results := a.getResults(field, modifiers.CoerceString(actual), a.caseSensitive)
	return results[needle], nil
}

type ahocorasickRe struct {
	*ahocorasickContains
}

// regexInfo is the per-pattern analysis needed by ahocorasickRe: the compiled
// regex plus the set of simple strings that necessarily appear if it matches.
// It is cached because MatchesField runs once per event per regex value, and
// both regexp.Compile and regexStrings are far more expensive than the match
// itself. Patterns come from rules so the cardinality is bounded by the ruleset.
type regexInfo struct {
	re              *regexp.Regexp
	necessary       []string
	caseInsensitive bool
}

var regexInfos sync.Map // map[string]*regexInfo

func getRegexInfo(pattern string) (*regexInfo, error) {
	if cached, ok := regexInfos.Load(pattern); ok {
		return cached.(*regexInfo), nil
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, err
	}
	// this function returns a set of simple strings
	// which necessarily appear if the regex matches
	// If none are present in the haystack, we don't need to run the regex
	ss, caseInsensitive, err := regexStrings(pattern)
	if err != nil {
		return nil, err
	}
	info := &regexInfo{re: re, necessary: ss, caseInsensitive: caseInsensitive}
	regexInfos.Store(pattern, info)
	return info, nil
}

func (a *ahocorasickRe) MatchesField(field string, actual any, expected any) (bool, error) {
	if actual == nil {
		// An absent field matches no regex (mirrors the standard re comparator).
		return false, nil
	}
	stringRe := modifiers.CoerceString(expected)
	info, err := getRegexInfo(stringRe)
	if err != nil {
		return false, err
	}
	re, ss, caseInsensitive := info.re, info.necessary, info.caseInsensitive

	haystack := modifiers.CoerceString(actual)

	// The trie prefilter only applies when this pattern has necessary substrings
	// and the field has a trie holding them; otherwise run the regex directly
	// (e.g. `.+`, which has no necessary substrings and may have contributed
	// nothing to the trie).
	if len(ss) > 0 {
		if results := a.getResults(field, haystack, !caseInsensitive); results != nil {
			found := false
			for _, s := range ss {
				if results[s] {
					found = true
					break
				}
			}
			if !found {
				return false, nil
			}
		}
	}

	// our cheap heuristic says the regex *might* match the string,
	// so we have to now run the full regex
	return re.MatchString(haystack), nil
}
