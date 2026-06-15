package aggregators

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/doracpphp/sigma-go"
	"github.com/doracpphp/sigma-go/evaluator"
	"github.com/doracpphp/sigma-go/internal/slidingstatistics"
)

// When the caller supplies the event timestamp via evaluator.WithEventTime, the
// count window must track event time, not wall-clock arrival time. Four failures
// spaced 10 minutes apart never put more than one event inside a 5m window, so a
// `count() > 3` rule must NOT fire even though all four are fed "instantly".
func TestCountUsesEventTime(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: Brute force
detection:
  failed:
    EventID: 4625
  condition: failed | count() by TargetUserName > 3
  timeframe: 5m
`))
	if err != nil {
		t.Fatal(err)
	}
	e := evaluator.ForRule(rule, InMemory(time.Hour)...)
	event := map[string]interface{}{"EventID": 4625, "TargetUserName": "alice"}

	base := time.Date(2021, 3, 15, 12, 0, 0, 0, time.UTC)
	var lastMatch bool
	for i := 0; i < 4; i++ {
		ctx := evaluator.WithEventTime(context.Background(), base.Add(time.Duration(i)*10*time.Minute))
		r, err := e.Matches(ctx, event)
		if err != nil {
			t.Fatal(err)
		}
		lastMatch = r.Match
	}
	if lastMatch {
		t.Fatal("events spaced beyond the 5m window must not accumulate to count() > 3")
	}

	// The same four events within the window (1 minute apart) DO fire.
	e2 := evaluator.ForRule(rule, InMemory(time.Hour)...)
	for i := 0; i < 4; i++ {
		ctx := evaluator.WithEventTime(context.Background(), base.Add(time.Duration(i)*time.Minute))
		r, err := e2.Matches(ctx, event)
		if err != nil {
			t.Fatal(err)
		}
		lastMatch = r.Match
	}
	if !lastMatch {
		t.Fatal("four events within the 5m window should fire count() > 3")
	}
}

// Brute force: count() by TargetUserName > 3 within a 5m timeframe.
// The rule's own timeframe must be honoured even though InMemory is
// constructed with a different (longer) default window.
func TestCountWithinRuleTimeframe(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: Brute force
detection:
  failed:
    EventID: 4625
  condition: failed | count() by TargetUserName > 3
  timeframe: 5m
`))
	if err != nil {
		t.Fatal(err)
	}

	// Default window is 1h, but the rule says 5m - the rule wins.
	e := evaluator.ForRule(rule, InMemory(time.Hour)...)
	ctx := context.Background()

	event := func(user string) map[string]interface{} {
		return map[string]interface{}{"EventID": 4625, "TargetUserName": user}
	}

	var lastMatch bool
	for i := 0; i < 4; i++ {
		r, err := e.Matches(ctx, event("alice"))
		if err != nil {
			t.Fatal(err)
		}
		lastMatch = r.Match
	}
	// 4 failures for alice (> 3) should fire.
	if !lastMatch {
		t.Fatal("expected count() > 3 to match after 4 failed logons")
	}

	// A different user is tracked independently and shouldn't fire.
	r, err := e.Matches(ctx, event("bob"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Match {
		t.Fatal("bob had only one failure, should not match")
	}
}

// Password spray: count(TargetUserName) by IpAddress > 3 - distinct usernames
// attempted from a single source IP.
func TestCountDistinct(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: Password spray
detection:
  failed:
    EventID: 4625
  condition: failed | count(TargetUserName) by IpAddress > 3
  timeframe: 10m
`))
	if err != nil {
		t.Fatal(err)
	}

	e := evaluator.ForRule(rule, InMemory(time.Hour)...)
	ctx := context.Background()

	event := func(ip, user string) map[string]interface{} {
		return map[string]interface{}{"EventID": 4625, "IpAddress": ip, "TargetUserName": user}
	}

	// Same IP, same user repeated: only 1 distinct username -> no match.
	for i := 0; i < 5; i++ {
		r, err := e.Matches(ctx, event("10.0.0.1", "alice"))
		if err != nil {
			t.Fatal(err)
		}
		if r.Match {
			t.Fatal("repeated single username should not count as a spray")
		}
	}

	// Same IP, 4 distinct usernames -> match on the 4th (> 3).
	users := []string{"u1", "u2", "u3", "u4"}
	var lastMatch bool
	for _, u := range users {
		r, err := e.Matches(ctx, event("10.0.0.2", u))
		if err != nil {
			t.Fatal(err)
		}
		lastMatch = r.Match
	}
	if !lastMatch {
		t.Fatal("expected 4 distinct usernames from one IP to match count(TargetUserName) > 3")
	}
}

// Distinct values that fall outside the sliding window must be dropped, so a
// slow trickle of usernames never accumulates into a false spray alert.
func TestDistinctTrackerWindowExpiry(t *testing.T) {
	d := &distinctTracker{window: 5 * time.Minute, lastSeen: map[string]time.Time{}}
	base := time.Now()

	if got := d.observe(base, "u1"); got != 1 {
		t.Fatalf("expected 1 distinct, got %v", got)
	}
	if got := d.observe(base.Add(1*time.Minute), "u2"); got != 2 {
		t.Fatalf("expected 2 distinct within window, got %v", got)
	}
	// 6 minutes after u1: u1 is now outside the 5m window and is pruned, so only
	// u2 (at +1m, age 5m... still in) and u3 remain.
	if got := d.observe(base.Add(6*time.Minute), "u3"); got != 2 {
		t.Fatalf("expected u1 to expire leaving 2 distinct, got %v", got)
	}
}

// count() by User, SourceIp > 2 - each (User, SourceIp) pair is an independent bucket.
func TestCountMultiFieldGroupBy(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: Multi group
detection:
  failed:
    EventID: 4625
  condition: failed | count() by User, SourceIp > 2
  timeframe: 5m
`))
	if err != nil {
		t.Fatal(err)
	}
	e := evaluator.ForRule(rule, InMemory(time.Hour)...)
	ctx := context.Background()
	evt := func(user, ip string) map[string]interface{} {
		return map[string]interface{}{"EventID": 4625, "User": user, "SourceIp": ip}
	}

	// alice from .1 three times -> fires (count 3 > 2).
	e.Matches(ctx, evt("alice", "10.0.0.1"))
	e.Matches(ctx, evt("alice", "10.0.0.1"))
	res, err := e.Matches(ctx, evt("alice", "10.0.0.1"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Match {
		t.Fatal("3 events for (alice,10.0.0.1) should fire")
	}

	// Same user but different IP is a different bucket -> independent count.
	res, _ = e.Matches(ctx, evt("alice", "10.0.0.2"))
	if res.Match {
		t.Fatal("(alice,10.0.0.2) is a separate bucket and has only one event")
	}
}

// max(FileSize) by Host > 1000000 - detect a large file written per host.
func TestMaxAggregation(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: Large file
detection:
  written:
    EventID: 11
  condition: written | max(FileSize) by Host > 1000000
  timeframe: 10m
`))
	if err != nil {
		t.Fatal(err)
	}

	e := evaluator.ForRule(rule, InMemory(time.Hour)...)
	ctx := context.Background()
	event := func(host string, size int) map[string]interface{} {
		return map[string]interface{}{"EventID": 11, "Host": host, "FileSize": size}
	}

	// Small files don't trip the threshold.
	r, err := e.Matches(ctx, event("h1", 500))
	if err != nil {
		t.Fatal(err)
	}
	if r.Match {
		t.Fatal("small file should not match max > 1000000")
	}

	// A large file on the same host pushes the windowed max over the threshold.
	r, err = e.Matches(ctx, event("h1", 2000000))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Match {
		t.Fatal("expected max(FileSize) > 1000000 to match after a large file")
	}

	// A different host is tracked independently.
	r, err = e.Matches(ctx, event("h2", 10))
	if err != nil {
		t.Fatal(err)
	}
	if r.Match {
		t.Fatal("host h2 only saw a tiny file, should not match")
	}
}

// min(ResponseBytes) by Endpoint < 10 - detect a suspiciously small response.
func TestMinAggregation(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: Tiny response
detection:
  resp:
    EventID: 1
  condition: resp | min(ResponseBytes) by Endpoint < 10
  timeframe: 10m
`))
	if err != nil {
		t.Fatal(err)
	}

	e := evaluator.ForRule(rule, InMemory(time.Hour)...)
	ctx := context.Background()
	event := func(ep string, size int) map[string]interface{} {
		return map[string]interface{}{"EventID": 1, "Endpoint": ep, "ResponseBytes": size}
	}

	r, err := e.Matches(ctx, event("/a", 500))
	if err != nil {
		t.Fatal(err)
	}
	if r.Match {
		t.Fatal("500 bytes should not match min < 10")
	}

	r, err = e.Matches(ctx, event("/a", 4))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Match {
		t.Fatal("expected min(ResponseBytes) < 10 to match after a 4 byte response")
	}
}

// Samples outside the window must be pruned so an old extreme stops counting.
func TestExtremeTrackerWindowExpiry(t *testing.T) {
	tr := &extremeTracker{window: 5 * time.Minute}
	base := time.Now()

	if got := tr.observeMax(base, 100); got != 100 {
		t.Fatalf("expected max 100, got %v", got)
	}
	// 6 minutes later the 100 sample has aged out of the 5m window.
	if got := tr.observeMax(base.Add(6*time.Minute), 5); got != 5 {
		t.Fatalf("expected the old max to expire leaving 5, got %v", got)
	}
}

// A rule that uses min/max but no implementation is wired should return a clear error.
func TestMinMaxWithoutImplementationErrors(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: Large file
detection:
  written:
    EventID: 11
  condition: written | max(FileSize) by Host > 1000000
`))
	if err != nil {
		t.Fatal(err)
	}

	e := evaluator.ForRule(rule) // no aggregation implementations
	_, err = e.Matches(context.Background(), map[string]interface{}{"EventID": 11, "Host": "h1", "FileSize": 2000000})
	if err == nil {
		t.Fatal("expected an error when max() is used without an implementation")
	}
}

// A rule that uses count() but no implementation is wired should return a clear
// error rather than silently doing nothing.
func TestCountWithoutImplementationErrors(t *testing.T) {
	rule, err := sigma.ParseRule([]byte(`
title: Brute force
detection:
  failed:
    EventID: 4625
  condition: failed | count() by TargetUserName > 3
`))
	if err != nil {
		t.Fatal(err)
	}

	e := evaluator.ForRule(rule) // no aggregation implementations
	_, err = e.Matches(context.Background(), map[string]interface{}{"EventID": 4625, "TargetUserName": "alice"})
	if err == nil {
		t.Fatal("expected an error when count() is used without an implementation")
	}
}

func TestSweepEvictsIdleEntries(t *testing.T) {
	i := &inMemory{
		timeframe: time.Minute,
		counts:    map[string]*tracked[*slidingstatistics.Counter]{},
		distincts: map[string]*tracked[*distinctTracker]{},
		averages:  map[string]*tracked[*slidingstatistics.Averager]{},
		sums:      map[string]*tracked[*slidingstatistics.Counter]{},
		extremes:  map[string]*tracked[*extremeTracker]{},
	}
	ctx := context.Background()

	for n := 0; n < 10; n++ {
		_, err := i.count(ctx, evaluator.GroupedByValues{EventValues: map[string]interface{}{"User": fmt.Sprint(n)}})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(i.counts) != 10 {
		t.Fatalf("expected 10 tracked groups, got %d", len(i.counts))
	}

	// Age out half the entries beyond 2x their window and force a sweep.
	aged := 0
	for _, tr := range i.counts {
		if aged == 5 {
			break
		}
		tr.lastSeen = time.Now().Add(-3 * time.Minute)
		aged++
	}
	i.ops = sweepInterval - 1
	i.maybeSweep(time.Now())

	if len(i.counts) != 5 {
		t.Fatalf("expected idle groups to be evicted, got %d remaining", len(i.counts))
	}

	// Still-active groups keep their state across the sweep.
	got, err := i.count(ctx, evaluator.GroupedByValues{EventValues: map[string]interface{}{"User": "fresh"}})
	if err != nil {
		t.Fatal(err)
	}
	if got != 1 {
		t.Fatalf("expected fresh group to start at 1, got %v", got)
	}
}

// The stale-entry (re-push) path: a value seen again after its heap entry was
// pushed must not be dropped until its *latest* sighting leaves the window.
func TestDistinctTrackerRefreshedValue(t *testing.T) {
	d := &distinctTracker{window: 5 * time.Minute, lastSeen: map[string]time.Time{}}
	base := time.Now()

	d.observe(base, "u1")
	d.observe(base.Add(4*time.Minute), "u1") // refresh u1 near the window edge
	// At +6m the original sighting (base) is expired but the refresh (+4m) is not.
	if got := d.observe(base.Add(6*time.Minute), "u2"); got != 2 {
		t.Fatalf("refreshed value must survive its first sighting expiring, got %v", got)
	}
	// At +10m the refresh has expired too.
	if got := d.observe(base.Add(10*time.Minute), "u3"); got != 2 {
		t.Fatalf("expected u1 gone and u2+u3 remaining, got %v", got)
	}
}

// The monotonic deque must keep older non-extreme samples that become the
// extreme once a newer extreme expires.
func TestExtremeTrackerDequeCorrectness(t *testing.T) {
	tr := &extremeTracker{window: 5 * time.Minute}
	base := time.Now()

	tr.observeMin(base, 10)
	if got := tr.observeMin(base.Add(time.Minute), 3); got != 3 {
		t.Fatalf("expected min 3, got %v", got)
	}
	// 7 is not the current min but must be retained: it becomes the min after 3 expires.
	if got := tr.observeMin(base.Add(2*time.Minute), 7); got != 3 {
		t.Fatalf("expected min 3, got %v", got)
	}
	// At +6m30s, 3 (at +1m) has expired; 7 (at +2m) is the min.
	if got := tr.observeMin(base.Add(6*time.Minute+30*time.Second), 9); got != 7 {
		t.Fatalf("expected min 7 after 3 expired, got %v", got)
	}
}

// The user-facing scaling scenario: 1M events within a 5-minute window must be
// processed in (amortised) constant time per observation, with exact results.
func TestTrackersHighRate(t *testing.T) {
	const n = 1_000_000
	base := time.Now()
	step := 5 * time.Minute / n

	d := &distinctTracker{window: 5 * time.Minute, lastSeen: map[string]time.Time{}}
	start := time.Now()
	var got float64
	for i := 0; i < n; i++ {
		// 100k distinct values, each seen repeatedly
		got = d.observe(base.Add(time.Duration(i)*step), fmt.Sprintf("v%d", i%100_000))
	}
	distinctElapsed := time.Since(start)
	if got != 100_000 {
		t.Fatalf("expected 100000 distinct values in window, got %v", got)
	}

	tr := &extremeTracker{window: 5 * time.Minute}
	start = time.Now()
	var minGot float64
	for i := 0; i < n; i++ {
		minGot = tr.observeMin(base.Add(time.Duration(i)*step), float64((i*7919)%1000))
	}
	extremeElapsed := time.Since(start)
	if minGot != 0 {
		t.Fatalf("expected min 0, got %v", minGot)
	}

	t.Logf("1M observations: distinct=%v extreme=%v", distinctElapsed, extremeElapsed)
	// Generous bound: quadratic behaviour would take minutes, not seconds.
	if distinctElapsed > 30*time.Second || extremeElapsed > 30*time.Second {
		t.Fatalf("trackers are too slow at high rates: distinct=%v extreme=%v", distinctElapsed, extremeElapsed)
	}
}

// With more group keys than one sweep batch, repeated sweeps must still evict
// all idle entries (partial sweeps rely on randomised map iteration order).
func TestSweepEventuallyEvictsBeyondBatch(t *testing.T) {
	m := map[string]*tracked[*slidingstatistics.Counter]{}
	stale := time.Now().Add(-time.Hour)
	for i := 0; i < 3*sweepBatch; i++ {
		m[fmt.Sprintf("k%d", i)] = &tracked[*slidingstatistics.Counter]{
			value:    slidingstatistics.Count(time.Minute),
			window:   time.Minute,
			lastSeen: stale,
		}
	}

	now := time.Now()
	for round := 0; round < 200 && len(m) > 0; round++ {
		sweep(m, now)
	}
	if len(m) != 0 {
		t.Fatalf("expected all idle entries evicted after repeated sweeps, %d remain", len(m))
	}
}
