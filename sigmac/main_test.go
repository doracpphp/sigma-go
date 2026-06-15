package main

import (
	"strings"
	"testing"

	"github.com/Velocidex/ordereddict"
)

// buildEvent constructs the nested structure produced by the evtx parser:
// {Event: {System: {...}, EventData/UserData: {...}}}.
func buildEvent(dataKey string, data *ordereddict.Dict) *ordereddict.Dict {
	sys := ordereddict.NewDict().
		Set("Provider", ordereddict.NewDict().Set("Name", "Microsoft-Windows-Security-Auditing")).
		Set("EventID", ordereddict.NewDict().Set("Value", 4625)).
		Set("Channel", "Security").
		Set("Computer", "HOST1").
		Set("TimeCreated", ordereddict.NewDict().Set("SystemTime", 1549731924.5)).
		Set("Execution", ordereddict.NewDict().Set("ProcessID", 1188).Set("ThreadID", 6576))
	event := ordereddict.NewDict().Set("System", sys)
	if data != nil {
		event.Set(dataKey, data)
	}
	return ordereddict.NewDict().Set("Event", event)
}

func TestFlattenEvent_EventData(t *testing.T) {
	data := ordereddict.NewDict().
		Set("TargetUserName", "alice").
		Set("IpAddress", "10.0.0.5").
		Set("LogonType", 3)
	out := flattenEvent(buildEvent("EventData", data))

	want := map[string]interface{}{
		"Provider_Name":  "Microsoft-Windows-Security-Auditing",
		"EventID":        4625,
		"Channel":        "Security",
		"Computer":       "HOST1",
		"ProcessID":      1188,
		"ThreadID":       6576,
		"TargetUserName": "alice",
		"IpAddress":      "10.0.0.5",
		"LogonType":      3,
	}
	for k, v := range want {
		if got, ok := out[k]; !ok || got != v {
			t.Errorf("field %q = %v (present=%v), want %v", k, got, ok, v)
		}
	}
	if _, ok := out["TimeCreated"]; !ok {
		t.Error("TimeCreated should be present")
	}
}

// UserData wraps the fields in a single sub-element which must be flattened one
// level deeper.
func TestFlattenEvent_UserData(t *testing.T) {
	inner := ordereddict.NewDict().
		Set("SubjectUserName", "test").
		Set("SubjectDomainName", "DOMAIN")
	data := ordereddict.NewDict().Set("LogFileCleared", inner)
	out := flattenEvent(buildEvent("UserData", data))

	if out["SubjectUserName"] != "test" {
		t.Errorf("SubjectUserName = %v, want test", out["SubjectUserName"])
	}
	if out["SubjectDomainName"] != "DOMAIN" {
		t.Errorf("SubjectDomainName = %v, want DOMAIN", out["SubjectDomainName"])
	}
}

// EventID may be a bare scalar instead of {Value: ...}.
func TestFlattenEvent_ScalarEventID(t *testing.T) {
	root := buildEvent("EventData", ordereddict.NewDict())
	event, _ := root.Get("Event")
	sys, _ := event.(*ordereddict.Dict).Get("System")
	sys.(*ordereddict.Dict).Set("EventID", 1102)

	out := flattenEvent(root)
	if out["EventID"] != 1102 {
		t.Errorf("EventID = %v, want 1102", out["EventID"])
	}
}

// The CSV record_id comes from the System block's EventRecordID (the real,
// global record number), not the parser's per-chunk Header.RecordID. Verify
// flattenEvent surfaces it so field(event, "EventRecordID") returns it.
func TestFlattenEvent_EventRecordID(t *testing.T) {
	root := buildEvent("EventData", ordereddict.NewDict())
	event, _ := root.Get("Event")
	sys, _ := event.(*ordereddict.Dict).Get("System")
	sys.(*ordereddict.Dict).Set("EventRecordID", 109446)

	out := flattenEvent(root)
	if got := field(out, "EventRecordID"); got != "109446" {
		t.Errorf("EventRecordID = %q, want %q", got, "109446")
	}
}

func TestEventTimestamp(t *testing.T) {
	// The fractional part is a float64 so its sub-second digits are not exact;
	// assert the second-resolution prefix.
	got := eventTimestamp(map[string]interface{}{"TimeCreated": 1549731924.6727583})
	if want := "2019-02-09T17:05:24."; !strings.HasPrefix(got, want) {
		t.Errorf("eventTimestamp = %q, want prefix %q", got, want)
	}
	if eventTimestamp(map[string]interface{}{}) != "" {
		t.Error("missing TimeCreated should yield empty string")
	}
}

func TestSplitYAMLDocs(t *testing.T) {
	docs := splitYAMLDocs([]byte("title: a\n---\ntitle: b\n"))
	if len(docs) != 2 {
		t.Fatalf("expected 2 documents, got %d", len(docs))
	}
	// A `---` inside a value (not on its own line) must not split.
	docs = splitYAMLDocs([]byte("title: a---b\n"))
	if len(docs) != 1 {
		t.Fatalf("expected 1 document, got %d", len(docs))
	}
}
