package evaluator

import (
	"context"
	"time"
)

// eventTimeKey is the context key under which the timestamp of the event being
// evaluated is carried.
type eventTimeKey struct{}

// WithEventTime returns a context carrying the timestamp of the event being
// evaluated. The in-memory aggregator and correlation evaluator window by this
// time instead of wall-clock arrival time, so aggregation/correlation results are
// correct when replaying historical logs (where every event "arrives" at once).
func WithEventTime(ctx context.Context, t time.Time) context.Context {
	return context.WithValue(ctx, eventTimeKey{}, t)
}

// EventTimeFromContext returns the event timestamp set by WithEventTime, or
// (zero, false) if none was set (callers fall back to time.Now()).
func EventTimeFromContext(ctx context.Context) (time.Time, bool) {
	t, ok := ctx.Value(eventTimeKey{}).(time.Time)
	return t, ok
}

// eventTimeOrNow returns the event timestamp from the context, or the current
// wall-clock time when none was provided.
func eventTimeOrNow(ctx context.Context) time.Time {
	if t, ok := EventTimeFromContext(ctx); ok {
		return t
	}
	return time.Now()
}
