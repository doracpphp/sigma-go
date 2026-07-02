package aggregators

import (
	"container/heap"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/doracpphp/sigma-go/evaluator"
	"github.com/doracpphp/sigma-go/internal/slidingstatistics"
)

type inMemory struct {
	sync.Mutex
	timeframe time.Duration
	counts    map[string]*tracked[*slidingstatistics.Counter]
	distincts map[string]*tracked[*distinctTracker]
	averages  map[string]*tracked[*slidingstatistics.Averager]
	sums      map[string]*tracked[*slidingstatistics.Counter]
	extremes  map[string]*tracked[*extremeTracker]
	ops       int
}

// tracked pairs an aggregation state with its window size and the last time it
// was touched, so that entries which have been idle for longer than their window
// (and therefore no longer influence any result) can be evicted. Without
// eviction the per-group-key state grows without bound on high-cardinality
// group-by fields.
type tracked[T any] struct {
	value    T
	window   time.Duration
	lastSeen time.Time
}

// sweepInterval is how many observations happen between eviction sweeps.
const sweepInterval = 4096

// sweepBatch bounds how many entries a single sweep examines per state map, so
// the pause while holding the lock stays bounded no matter how many group keys
// exist. Go map iteration starts at a random position, so successive partial
// sweeps eventually visit every entry (the same sampling approach Redis uses
// for TTL eviction). The batch is a multiple of the interval so eviction keeps
// up with creation: at most sweepInterval new keys appear between sweeps and
// each sweep examines 4x that.
const sweepBatch = 4 * sweepInterval

// getTracked returns (creating if needed) the state for a group key and marks it
// as touched now.
func getTracked[T any](m map[string]*tracked[T], key string, window time.Duration, now time.Time, create func() T) T {
	t, ok := m[key]
	if !ok {
		t = &tracked[T]{value: create(), window: window}
		m[key] = t
	}
	t.lastSeen = now
	return t.value
}

func sweep[T any](m map[string]*tracked[T], now time.Time) {
	scanned := 0
	for key, t := range m {
		scanned++
		if scanned > sweepBatch {
			break
		}
		// An entry idle for more than twice its window can no longer affect any
		// result (the sliding windows only look one window back), so drop it.
		if now.Sub(t.lastSeen) > 2*t.window {
			delete(m, key)
		}
	}
}

// maybeSweep evicts idle entries from all the state maps every sweepInterval
// observations. Callers must hold the lock.
func (i *inMemory) maybeSweep(now time.Time) {
	i.ops++
	if i.ops%sweepInterval != 0 {
		return
	}
	sweep(i.counts, now)
	sweep(i.distincts, now)
	sweep(i.averages, now)
	sweep(i.sums, now)
	sweep(i.extremes, now)
}

// window returns the sliding-window size to use for a given aggregation.
// Rules can specify their own `detection.timeframe`, which takes precedence
// over the default timeframe configured when constructing the aggregator.
func (i *inMemory) window(groupBy evaluator.GroupedByValues) time.Duration {
	if groupBy.Timeframe > 0 {
		return groupBy.Timeframe
	}
	return i.timeframe
}

// eventNow returns the timestamp of the event being evaluated (so aggregation
// windows track event time, correct for offline replay), falling back to the
// current wall-clock time when the caller didn't supply one.
func eventNow(ctx context.Context) time.Time {
	if t, ok := evaluator.EventTimeFromContext(ctx); ok {
		return t
	}
	return time.Now()
}

func (i *inMemory) count(ctx context.Context, groupBy evaluator.GroupedByValues) (float64, error) {
	i.Lock()
	defer i.Unlock()
	now := eventNow(ctx)
	i.maybeSweep(now)
	window := i.window(groupBy)
	c := getTracked(i.counts, groupBy.Key(), window, now, func() *slidingstatistics.Counter {
		return slidingstatistics.Count(window)
	})

	return float64(c.IncrementN(now, 1)), nil
}

// countDistinct counts the number of distinct values seen for a group within the
// sliding window. This backs aggregations like `count(TargetUserName) by IpAddress`.
func (i *inMemory) countDistinct(ctx context.Context, groupBy evaluator.GroupedByValues, value interface{}) (float64, error) {
	i.Lock()
	defer i.Unlock()
	now := eventNow(ctx)
	i.maybeSweep(now)
	window := i.window(groupBy)
	t := getTracked(i.distincts, groupBy.Key(), window, now, func() *distinctTracker {
		return &distinctTracker{window: window, lastSeen: map[string]time.Time{}}
	})

	return t.observe(now, fmt.Sprint(value)), nil
}

func (i *inMemory) average(ctx context.Context, groupBy evaluator.GroupedByValues, value float64) (float64, error) {
	i.Lock()
	defer i.Unlock()
	now := eventNow(ctx)
	i.maybeSweep(now)
	window := i.window(groupBy)
	a := getTracked(i.averages, groupBy.Key(), window, now, func() *slidingstatistics.Averager {
		return slidingstatistics.Average(window)
	})

	return a.Average(now, value), nil
}

func (i *inMemory) sum(ctx context.Context, groupBy evaluator.GroupedByValues, value float64) (float64, error) {
	i.Lock()
	defer i.Unlock()
	now := eventNow(ctx)
	i.maybeSweep(now)
	window := i.window(groupBy)
	a := getTracked(i.sums, groupBy.Key(), window, now, func() *slidingstatistics.Counter {
		return slidingstatistics.Count(window)
	})

	return a.IncrementN(now, value), nil
}

func (i *inMemory) min(ctx context.Context, groupBy evaluator.GroupedByValues, value float64) (float64, error) {
	i.Lock()
	defer i.Unlock()
	now := eventNow(ctx)
	i.maybeSweep(now)
	window := i.window(groupBy)
	t := getTracked(i.extremes, groupBy.Key(), window, now, func() *extremeTracker {
		return &extremeTracker{window: window}
	})
	return t.observeMin(now, value), nil
}

func (i *inMemory) max(ctx context.Context, groupBy evaluator.GroupedByValues, value float64) (float64, error) {
	i.Lock()
	defer i.Unlock()
	now := eventNow(ctx)
	i.maybeSweep(now)
	window := i.window(groupBy)
	t := getTracked(i.extremes, groupBy.Key(), window, now, func() *extremeTracker {
		return &extremeTracker{window: window}
	})
	return t.observeMax(now, value), nil
}

// extremeTracker computes the min/max over a sliding window using monotonic
// deques (the standard sliding-window-minimum algorithm): when a new sample
// arrives, older samples that can never again be the extreme (because the new
// sample is at least as extreme and newer) are dropped from the back, and
// samples that have aged out of the window are dropped from the front. Each
// sample is pushed and popped at most once, so an observation is O(1)
// amortised regardless of the event rate.
type extremeTracker struct {
	window time.Duration
	minDQ  []sample // values strictly increasing front to back; front is the window min
	maxDQ  []sample // values strictly decreasing front to back; front is the window max
}

type sample struct {
	at    time.Time
	value float64
}

func (e *extremeTracker) observeMin(now time.Time, value float64) float64 {
	for len(e.minDQ) > 0 && e.minDQ[len(e.minDQ)-1].value >= value {
		e.minDQ = e.minDQ[:len(e.minDQ)-1]
	}
	e.minDQ = append(e.minDQ, sample{at: now, value: value})
	cutoff := now.Add(-e.window)
	for e.minDQ[0].at.Before(cutoff) {
		e.minDQ = e.minDQ[1:]
	}
	return e.minDQ[0].value
}

func (e *extremeTracker) observeMax(now time.Time, value float64) float64 {
	for len(e.maxDQ) > 0 && e.maxDQ[len(e.maxDQ)-1].value <= value {
		e.maxDQ = e.maxDQ[:len(e.maxDQ)-1]
	}
	e.maxDQ = append(e.maxDQ, sample{at: now, value: value})
	cutoff := now.Add(-e.window)
	for e.maxDQ[0].at.Before(cutoff) {
		e.maxDQ = e.maxDQ[1:]
	}
	return e.maxDQ[0].value
}

// distinctTracker keeps the last-seen timestamp of each distinct value for a
// single group and reports how many remain inside the sliding window.
//
// Expiry is driven by a min-heap ordered by timestamp rather than scanning the
// whole map on every observation (which would be quadratic at high event
// rates). Invariant: every value in lastSeen has exactly one entry in expiry.
// A heap entry may be stale (the value was seen again after the entry was
// pushed); popping a stale entry re-pushes it at the value's true last-seen
// time, so the reported count is always exact.
type distinctTracker struct {
	window   time.Duration
	lastSeen map[string]time.Time
	expiry   expiryHeap
}

type expiryEntry struct {
	at    time.Time
	value string
}

type expiryHeap []expiryEntry

func (h expiryHeap) Len() int            { return len(h) }
func (h expiryHeap) Less(i, j int) bool  { return h[i].at.Before(h[j].at) }
func (h expiryHeap) Swap(i, j int)       { h[i], h[j] = h[j], h[i] }
func (h *expiryHeap) Push(x interface{}) { *h = append(*h, x.(expiryEntry)) }
func (h *expiryHeap) Pop() interface{} {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[:n-1]
	return x
}

func (d *distinctTracker) observe(now time.Time, value string) float64 {
	if _, ok := d.lastSeen[value]; !ok {
		heap.Push(&d.expiry, expiryEntry{at: now, value: value})
	}
	d.lastSeen[value] = now

	cutoff := now.Add(-d.window)
	for len(d.expiry) > 0 && d.expiry[0].at.Before(cutoff) {
		e := heap.Pop(&d.expiry).(expiryEntry)
		last := d.lastSeen[e.value]
		if last.After(e.at) {
			// Stale entry: the value was seen again since. Re-push at its true
			// last-seen time (which may itself already be expired, in which case
			// the next loop iteration deletes it).
			heap.Push(&d.expiry, expiryEntry{at: last, value: e.value})
			continue
		}
		delete(d.lastSeen, e.value)
	}
	return float64(len(d.lastSeen))
}

func InMemory(timeframe time.Duration) []evaluator.Option {
	if timeframe <= 0 {
		// A zero/negative default window would make the sliding counters divide
		// by zero for rules without their own `detection.timeframe`.
		timeframe = time.Hour
	}
	i := &inMemory{
		timeframe: timeframe,
		counts:    map[string]*tracked[*slidingstatistics.Counter]{},
		distincts: map[string]*tracked[*distinctTracker]{},
		averages:  map[string]*tracked[*slidingstatistics.Averager]{},
		sums:      map[string]*tracked[*slidingstatistics.Counter]{},
		extremes:  map[string]*tracked[*extremeTracker]{},
	}

	return []evaluator.Option{
		evaluator.CountImplementation(i.count),
		evaluator.CountDistinctImplementation(i.countDistinct),
		evaluator.SumImplementation(i.sum),
		evaluator.AverageImplementation(i.average),
		evaluator.MinImplementation(i.min),
		evaluator.MaxImplementation(i.max),
	}
}
