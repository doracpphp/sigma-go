package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/doracpphp/sigma-go"
	"github.com/doracpphp/sigma-go/evaluator"
	"github.com/doracpphp/sigma-go/evaluator/aggregators"
)

// A `---` separator followed by a comment is a legal YAML document boundary and
// must split; missing it silently drops every rule after it.
func TestSplitYAMLDocsWithTrailingComment(t *testing.T) {
	contents := []byte(`title: first
detection:
  s:
    EventID: 1
  condition: s
--- # second rule
title: second
detection:
  s:
    EventID: 2
  condition: s
`)
	docs, err := splitYAMLDocs(contents)
	if err != nil {
		t.Fatal(err)
	}
	var nonEmpty int
	for _, d := range docs {
		if strings.TrimSpace(string(d)) != "" {
			nonEmpty++
		}
	}
	if nonEmpty != 2 {
		t.Fatalf("expected 2 documents, got %d", nonEmpty)
	}
}

// A line that merely starts with --- inside content must not split.
func TestSplitYAMLDocsNoFalseSplit(t *testing.T) {
	contents := []byte("title: a\ndescription: |\n  ---not a separator because of trailing text---\n")
	if docs, err := splitYAMLDocs(contents); err != nil || len(docs) != 1 {
		t.Fatalf("expected 1 document, got %d (err=%v)", len(docs), err)
	}
}

// A bare `---` line inside a block scalar is content, not a document separator.
// The old regex-based splitter split here, and both halves then failed to parse
// so the whole rule was silently dropped.
func TestSplitYAMLDocsBlockScalar(t *testing.T) {
	contents := []byte("title: a\ndescription: |\n  first line\n  ---\n  second line\ndetection:\n  s:\n    EventID: 1\n  condition: s\n")
	docs, err := splitYAMLDocs(contents)
	if err != nil || len(docs) != 1 {
		t.Fatalf("expected 1 document, got %d (err=%v)", len(docs), err)
	}
	rule, err := sigma.ParseRule(docs[0])
	if err != nil {
		t.Fatalf("re-encoded document failed to parse: %v", err)
	}
	if want := "first line\n---\nsecond line\n"; rule.Description != want {
		t.Errorf("description = %q, want %q", rule.Description, want)
	}
}

// The channel filter must be applied BEFORE evaluation, not just when printing
// rows: a stateful count() rule must never see events from channels its
// logsource doesn't target, or wrong-channel events inflate the counter and the
// rule false-positives on the first legitimate event.
func TestChannelFilterAppliedBeforeAggregation(t *testing.T) {
	defer func() { channelFilterEnabled = true }()
	channelFilterEnabled = true

	rule, err := sigma.ParseRule([]byte(`
title: brute force
id: 22222222-2222-2222-2222-222222222222
logsource:
  service: security
detection:
  s:
    EventID: 4625
  timeframe: 10m
  condition: s | count() > 1
`))
	if err != nil {
		t.Fatal(err)
	}
	var options []evaluator.Option
	options = append(options, aggregators.InMemory(time.Hour)...)
	groups := buildBundles([]sigma.Rule{rule}, options...)

	ctx := context.Background()
	event := func(channel string) map[string]interface{} {
		return map[string]interface{}{"EventID": 4625, "Channel": channel}
	}

	// Search-matching events from the wrong channel: no rows, and crucially they
	// must not increment the count() state.
	for i := 0; i < 2; i++ {
		if rows := matchEvent(ctx, event("Microsoft-Windows-Sysmon/Operational"), "f.evtx", "1", groups, nil); len(rows) != 0 {
			t.Fatalf("wrong-channel event %d produced %d row(s)", i, len(rows))
		}
	}
	// First legitimate Security event: count is 1, not > 1, so no alert. Before
	// the fix the two Sysmon events had already pushed the counter to 2.
	if rows := matchEvent(ctx, event("Security"), "f.evtx", "2", groups, nil); len(rows) != 0 {
		t.Fatalf("first Security event fired the count() rule: counter was polluted by wrong-channel events (%d rows)", len(rows))
	}
	// Second Security event: count is 2 > 1, the rule should fire now.
	if rows := matchEvent(ctx, event("Security"), "f.evtx", "3", groups, nil); len(rows) != 1 {
		t.Fatalf("second Security event should fire the count() rule, got %d row(s)", len(rows))
	}
}

func TestSanitizeCSVRow(t *testing.T) {
	row := []string{"=cmd|'/c calc'!A1", "+1", "-2", "@x", "safe", "", `{"json":true}`}
	sanitizeCSVRow(row)
	want := []string{"'=cmd|'/c calc'!A1", "'+1", "'-2", "'@x", "safe", "", `{"json":true}`}
	for i := range want {
		if row[i] != want[i] {
			t.Errorf("cell %d = %q, want %q", i, row[i], want[i])
		}
	}
}
