package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadExcludeIDs(t *testing.T) {
	dir := t.TempDir()
	// Mirrors Hayabusa's exclude_rules.txt / noisy_rules.txt format.
	exclude := filepath.Join(dir, "exclude_rules.txt")
	if err := os.WriteFile(exclude, []byte(`# Replaced by Hayabusa rules:
23f0b75b-66c0-4895-ae63-4243fa898109 # "Security Event Log Cleared"
53facd0f-d88d-bab7-469e-a36211463245 # Quick Execution of a Series of Suspicious Commands

# Test Files
00000000-0000-0000-0000-000000000000 # TestFile
`), 0o644); err != nil {
		t.Fatal(err)
	}
	noisy := filepath.Join(dir, "noisy_rules.txt")
	if err := os.WriteFile(noisy, []byte("#Hayabusa rules\n0090ea60-f4a2-43a8-8657-3a9a4ddcf547 # Sysmon 6 Driver Loaded\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	ids, err := loadExcludeIDs(exclude + "," + noisy)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"23f0b75b-66c0-4895-ae63-4243fa898109",
		"53facd0f-d88d-bab7-469e-a36211463245",
		"00000000-0000-0000-0000-000000000000",
		"0090ea60-f4a2-43a8-8657-3a9a4ddcf547",
	}
	if len(ids) != len(want) {
		t.Fatalf("got %d ids, want %d: %v", len(ids), len(want), ids)
	}
	for _, id := range want {
		if !ids[id] {
			t.Errorf("missing excluded id %q", id)
		}
	}
	// Empty spec yields an empty set, no error.
	empty, err := loadExcludeIDs("")
	if err != nil || len(empty) != 0 {
		t.Fatalf("empty spec: got %v err %v", empty, err)
	}

	// A missing file is an error.
	if _, err := loadExcludeIDs(filepath.Join(dir, "nope.txt")); err == nil {
		t.Error("expected error for missing exclude file")
	}
}
