package sigma

import (
	"github.com/google/go-cmp/cmp/cmpopts"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bradleyjkemp/cupaloy/v2"
	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v3"
)

func TestParseRule(t *testing.T) {
	err := filepath.Walk("./testdata/", func(path string, info os.FileInfo, err error) error {
		if !strings.HasSuffix(path, ".rule.yml") {
			return nil
		}

		t.Run(strings.TrimSuffix(filepath.Base(path), ".rule.yml"), func(t *testing.T) {
			contents, err := ioutil.ReadFile(path)
			if err != nil {
				t.Fatalf("failed reading test input: %v", err)
			}

			rule, err := ParseRule(contents)
			if err != nil {
				t.Fatalf("error parsing rule: %v", err)
			}

			cupaloy.New(cupaloy.SnapshotSubdirectory("testdata")).SnapshotT(t, rule)
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMarshalRule(t *testing.T) {
	err := filepath.Walk("./testdata/", func(path string, info os.FileInfo, err error) error {
		if !strings.HasSuffix(path, ".rule.yml") {
			return nil
		}

		t.Run(strings.TrimSuffix(filepath.Base(path), ".rule.yml"), func(t *testing.T) {
			contents, err := ioutil.ReadFile(path)
			if err != nil {
				t.Fatalf("failed reading test input: %v", err)
			}

			rule, err := ParseRule(contents)
			if err != nil {
				t.Fatalf("error parsing rule: %v", err)
			}

			// Create a new temporary file in our testing temp directory
			stream, err := os.CreateTemp(t.TempDir(), filepath.Base(path))
			if err != nil {
				t.Fatalf("error creating temp rule file: %v", err)
			}
			defer os.Remove(stream.Name())
			defer stream.Close()

			// Save the rule to a temporary file
			encoder := yaml.NewEncoder(stream)
			if err := encoder.Encode(&rule); err != nil {
				t.Fatalf("error encoding rule to file: %v", err)
			}

			// Return to the beginning of the stream
			stream.Seek(0, os.SEEK_SET)

			// Re-read the rule from the newly serialized file
			var rule_copy Rule
			decoder := yaml.NewDecoder(stream)
			if err := decoder.Decode(&rule_copy); err != nil {
				t.Fatalf("error decoding rule copy: %v", err)
			}

			if !cmp.Equal(rule, rule_copy, cmpopts.IgnoreUnexported(Condition{}, FieldMatcher{}, Search{})) {
				t.Fatalf("rule and marshalled copy are not equal")
			}
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestParseRule_TimeframeDays(t *testing.T) {
	rule, err := ParseRule([]byte(`
title: legacy day-unit timeframe
detection:
  selection:
    EventID: 4625
  timeframe: 30d
  condition: selection | count() > 5
`))
	if err != nil {
		t.Fatal(err)
	}
	if want := 30 * 24 * time.Hour; rule.Detection.Timeframe != want {
		t.Fatalf("timeframe = %v, want %v", rule.Detection.Timeframe, want)
	}

	// Go duration syntax keeps working
	rule, err = ParseRule([]byte(`
title: go-syntax timeframe
detection:
  selection:
    EventID: 4625
  timeframe: 1h30m
  condition: selection | count() > 5
`))
	if err != nil {
		t.Fatal(err)
	}
	if want := 90 * time.Minute; rule.Detection.Timeframe != want {
		t.Fatalf("timeframe = %v, want %v", rule.Detection.Timeframe, want)
	}
}
