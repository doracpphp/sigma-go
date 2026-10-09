package main

import (
	"context"
	"os"
	"path/filepath"
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

const procCreationRule = `
title: cmd started
name: cmd_started
id: 33333333-3333-3333-3333-333333333333
logsource:
  product: windows
  category: process_creation
detection:
  s:
    Image|endswith: '\cmd.exe'
  condition: s
`

// Sysmon logs every category to one channel, so the channel alone doesn't
// scope a process_creation rule: a network connection (EID 3) made by cmd.exe
// carries the same Image field and must not match.
func TestCategoryRulesScopedByEventID(t *testing.T) {
	defer func() { channelFilterEnabled = true }()
	channelFilterEnabled = true

	rule, err := sigma.ParseRule([]byte(procCreationRule))
	if err != nil {
		t.Fatal(err)
	}
	groups := buildBundles([]sigma.Rule{rule})
	ctx := context.Background()
	event := func(eventID int) map[string]interface{} {
		return map[string]interface{}{
			"Channel": "Microsoft-Windows-Sysmon/Operational",
			"EventID": eventID,
			"Image":   `C:\Windows\System32\cmd.exe`,
		}
	}
	if rows := matchEvent(ctx, event(3), "f.evtx", "1", groups, nil); len(rows) != 0 {
		t.Fatalf("process_creation rule matched a Sysmon network connection event (%d rows)", len(rows))
	}
	if rows := matchEvent(ctx, event(1), "f.evtx", "2", groups, nil); len(rows) != 1 {
		t.Fatalf("process_creation rule should match Sysmon EID 1, got %d row(s)", len(rows))
	}
}

// The rules a correlation evaluates internally get the same channel/event ID
// scoping, and a referenced rule only alerts on its own with `generate: true`.
func TestCorrelationScopingAndGenerate(t *testing.T) {
	defer func() { channelFilterEnabled = true }()
	channelFilterEnabled = true

	dir := t.TempDir()
	write := func(name, contents string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(contents), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("proc.yml", procCreationRule)
	write("corr.yml", `
title: cmd burst
id: 44444444-4444-4444-4444-444444444444
correlation:
  type: event_count
  rules: [cmd_started]
  timespan: 10m
  condition:
    gte: 2
`)
	rules, err := loadRules(dir)
	if err != nil {
		t.Fatal(err)
	}
	ce, err := evaluator.ForCorrelation(rules[0], rules, evaluator.WithEventFilter(logsourceFilter))
	if err != nil {
		t.Fatal(err)
	}
	correlations := []corrEntry{{ce: ce, channels: correlationChannels(rules[0], rules)}}
	hidden := hiddenByCorrelations(correlations)
	detection := withoutHidden([]sigma.Rule{rules[1]}, hidden)
	if len(detection) != 0 {
		t.Fatalf("a rule referenced by a correlation without generate: true must not alert on its own")
	}
	groups := buildBundles(detection)

	ctx := context.Background()
	base := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	event := func(eventID int, at time.Duration) map[string]interface{} {
		return map[string]interface{}{
			"Channel":     "Microsoft-Windows-Sysmon/Operational",
			"EventID":     eventID,
			"Image":       `C:\Windows\System32\cmd.exe`,
			"TimeCreated": float64(base.Add(at).Unix()),
		}
	}
	// Network connections and image loads of cmd.exe are not process creations
	// and must not count towards the correlation.
	for i, eid := range []int{3, 7, 1} {
		if rows := matchEvent(ctx, event(eid, time.Duration(i)*time.Second), "f.evtx", "1", groups, correlations); len(rows) != 0 {
			t.Fatalf("event %d (EID %d) fired %d row(s); out-of-scope events counted", i, eid, len(rows))
		}
	}
	rows := matchEvent(ctx, event(1, 5*time.Second), "f.evtx", "2", groups, correlations)
	if len(rows) != 1 || rows[0][6] != "44444444-4444-4444-4444-444444444444" {
		t.Fatalf("second process creation should fire only the correlation, got %v", rows)
	}

	// With generate: true the referenced rule alerts on its own as well.
	rules[0].Correlation.Generate = true
	ce, err = evaluator.ForCorrelation(rules[0], rules)
	if err != nil {
		t.Fatal(err)
	}
	if hidden := hiddenByCorrelations([]corrEntry{{ce: ce}}); len(withoutHidden([]sigma.Rule{rules[1]}, hidden)) != 1 {
		t.Fatal("generate: true must keep the referenced rule's own alerts")
	}
}

// Rules for other products reuse Windows field names (Image, CommandLine) and
// would false-positive on evtx events.
func TestTargetsWindows(t *testing.T) {
	for _, tc := range []struct {
		ls   sigma.Logsource
		want bool
	}{
		{sigma.Logsource{}, true},
		{sigma.Logsource{Product: "windows"}, true},
		{sigma.Logsource{Product: "Windows", Category: "webserver"}, true},
		{sigma.Logsource{Product: "linux", Category: "process_creation"}, false},
		{sigma.Logsource{Product: "macos"}, false},
		// Product-less rules for other log types: a `category: database` rule
		// with the keyword "dump" matched every comsvcs MiniDump command line.
		{sigma.Logsource{Category: "database"}, false},
		{sigma.Logsource{Category: "webserver"}, false},
		{sigma.Logsource{Category: "dns"}, false},
		{sigma.Logsource{Service: "apache"}, false},
		// ...but known Windows sources without a product are kept.
		{sigma.Logsource{Category: "process_creation"}, true},
		{sigma.Logsource{Service: "security"}, true},
	} {
		if got := targetsWindows(tc.ls); got != tc.want {
			t.Errorf("targetsWindows(%+v) = %v, want %v", tc.ls, got, tc.want)
		}
	}
}
