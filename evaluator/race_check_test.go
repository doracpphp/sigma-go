package evaluator_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/doracpphp/sigma-go"
	"github.com/doracpphp/sigma-go/evaluator"
	"github.com/doracpphp/sigma-go/evaluator/aggregators"
)

// Callers processing large logs will want to call Matches from multiple
// goroutines; this exercises the bundle (incl. the shared pattern caches and
// aggregation state) under the race detector.
func TestBundleMatchesConcurrently(t *testing.T) {
	var rules []sigma.Rule
	for _, y := range []string{`
title: contains rule
detection:
  s:
    CommandLine|contains: 'mimikatz'
  condition: s
`, `
title: regex rule
detection:
  s:
    CommandLine|re: 'enc\s+[A-Za-z0-9+/=]+'
  condition: s
`, `
title: agg rule
detection:
  s:
    EventID: 4625
  timeframe: 5m
  condition: s | count() by User > 3
`, `
title: wildcard rule
detection:
  s:
    TargetFilename: '*\lsass.dmp'
  condition: s
`} {
		rule, err := sigma.ParseRule([]byte(y))
		if err != nil {
			t.Fatal(err)
		}
		rules = append(rules, rule)
	}

	bundle := evaluator.ForRules(rules, aggregators.InMemory(5*time.Minute)...)

	events := []map[string]interface{}{
		{"CommandLine": "powershell -enc AAAA", "EventID": 1},
		{"CommandLine": "Invoke-Mimikatz", "EventID": 1},
		{"EventID": 4625, "User": "alice"},
		{"TargetFilename": `C:\temp\lsass.dmp`},
	}

	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(seed int) {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				if _, err := bundle.Matches(context.Background(), events[(seed+i)%len(events)]); err != nil {
					t.Error(err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
}
