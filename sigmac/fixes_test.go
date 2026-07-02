package main

import (
	"strings"
	"testing"
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
	docs := splitYAMLDocs(contents)
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
	if docs := splitYAMLDocs(contents); len(docs) != 1 {
		t.Fatalf("expected 1 document, got %d", len(docs))
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
