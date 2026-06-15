// Command sigmac scans Windows .evtx event logs against a set of Sigma rules
// and writes the matching events to CSV.
//
// Usage:
//
//	sigmac -rules ./rules [-config config.yml] [-out alerts.csv] file1.evtx [file2.evtx ...]
//
// Rules may be a single .yml file or a directory (scanned recursively for
// .yml/.yaml). Detection rules (including count()/aggregation rules) are
// evaluated together as a single bundle; Sigma correlation rules are evaluated
// separately. Aggregation and correlation windows use wall-clock arrival time,
// so on historical replay their results are approximate (see the note printed
// at startup).
package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/Velocidex/ordereddict"
	"www.velocidex.com/golang/evtx"

	"github.com/doracpphp/sigma-go"
	"github.com/doracpphp/sigma-go/evaluator"
	"github.com/doracpphp/sigma-go/evaluator/aggregators"
)

func main() {
	fs := flag.NewFlagSet("sigmac", flag.ExitOnError)
	rulesPath := fs.String("rules", "", "Sigma rule file or directory (required)")
	configPath := fs.String("config", "", "optional Sigma config file (field mappings)")
	outPath := fs.String("out", "", "output CSV file (default: stdout)")
	timeframe := fs.Duration("timeframe", time.Hour, "default sliding window for aggregation rules without their own timeframe")
	channelFilter := fs.Bool("channel-filter", true, "only evaluate a rule against events from the channel its logsource targets (faster, fewer cross-channel matches)")
	exclude := fs.String("exclude", "", "comma-separated files of rule IDs to skip, in `<uuid> # comment` format (e.g. Hayabusa's exclude_rules.txt,noisy_rules.txt)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: sigmac -rules <file|dir> [-config c.yml] [-out alerts.csv] <file.evtx> ...")
		fmt.Fprintln(os.Stderr, "  <file.evtx> is one or more .evtx event log files")
		fs.PrintDefaults()
	}

	// Parse flags and positional arguments in any order (Go's flag package
	// otherwise stops at the first positional argument).
	var inputs []string
	args := os.Args[1:]
	for len(args) > 0 {
		if err := fs.Parse(args); err != nil {
			os.Exit(2)
		}
		args = fs.Args()
		if len(args) > 0 {
			inputs = append(inputs, args[0])
			args = args[1:]
		}
	}

	if *rulesPath == "" || len(inputs) == 0 {
		fs.Usage()
		os.Exit(2)
	}
	channelFilterEnabled = *channelFilter

	excludeIDs, err := loadExcludeIDs(*exclude)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}

	if err := run(*rulesPath, *configPath, *outPath, *timeframe, inputs, excludeIDs); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// loadExcludeIDs reads rule IDs to skip from the given comma-separated list of
// files. Each line is `<uuid>` optionally followed by `# comment`; blank lines and
// lines starting with `#` are ignored. This accepts Hayabusa's exclude_rules.txt /
// noisy_rules.txt verbatim.
func loadExcludeIDs(spec string) (map[string]bool, error) {
	ids := map[string]bool{}
	for _, path := range strings.Split(spec, ",") {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		contents, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("reading exclude file: %w", err)
		}
		for _, line := range strings.Split(string(contents), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			ids[strings.ToLower(strings.Fields(line)[0])] = true
		}
	}
	return ids, nil
}

func run(rulesPath, configPath, outPath string, timeframe time.Duration, inputs []string, excludeIDs map[string]bool) error {
	rules, err := loadRules(rulesPath)
	if err != nil {
		return err
	}
	if len(excludeIDs) > 0 {
		kept := rules[:0]
		excluded := 0
		for _, r := range rules {
			if r.ID != "" && excludeIDs[strings.ToLower(r.ID)] {
				excluded++
				continue
			}
			kept = append(kept, r)
		}
		rules = kept
		fmt.Fprintf(os.Stderr, "excluded %d rule(s) by ID\n", excluded)
	}
	if len(rules) == 0 {
		return fmt.Errorf("no valid Sigma rules found in %s", rulesPath)
	}

	var options []evaluator.Option
	options = append(options, aggregators.InMemory(timeframe)...)
	if configPath != "" {
		contents, err := os.ReadFile(configPath)
		if err != nil {
			return fmt.Errorf("reading config: %w", err)
		}
		config, err := sigma.ParseConfig(contents)
		if err != nil {
			return fmt.Errorf("parsing config: %w", err)
		}
		options = append(options, evaluator.WithConfig(config))
	}

	// Split detection rules (evaluated together as a bundle) from correlation
	// rules (each evaluated against the full rule set it references).
	var detectionRules []sigma.Rule
	var correlationRules []sigma.Rule
	for _, r := range rules {
		if r.Correlation != nil {
			correlationRules = append(correlationRules, r)
		} else {
			detectionRules = append(detectionRules, r)
		}
	}

	bundle := evaluator.ForRules(detectionRules, options...)

	var correlations []*evaluator.CorrelationEvaluator
	for _, r := range correlationRules {
		ce, err := evaluator.ForCorrelation(r, rules, options...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping correlation rule %q: %v\n", r.Title, err)
			continue
		}
		correlations = append(correlations, ce)
	}

	fmt.Fprintf(os.Stderr, "loaded %d detection rule(s), %d correlation rule(s)\n", len(detectionRules), len(correlations))
	if hasAggregation(detectionRules) || len(correlations) > 0 {
		fmt.Fprintln(os.Stderr, "note: aggregation/correlation windows use wall-clock arrival time; on historical replay these results are approximate")
	}

	out := os.Stdout
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			return err
		}
		defer f.Close()
		out = f
	}
	w := csv.NewWriter(out)
	defer w.Flush()
	header := []string{
		"timestamp", "source_file", "record_id", "computer", "channel", "event_id",
		"rule_id", "rule_title", "rule_level", "rule_tags", "event_json",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	ctx := context.Background()
	var scanned, matched int
	for _, path := range inputs {
		n, m, err := scanFile(ctx, path, bundle, correlations, w)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", path, err)
			continue
		}
		scanned += n
		matched += m
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "scanned %d event(s), wrote %d alert row(s)\n", scanned, matched)
	return nil
}

// scanFile parses one evtx file and writes a CSV row for every (event, matching
// rule) pair. It returns the number of events scanned and alert rows written.
func scanFile(ctx context.Context, path string, bundle evaluator.RuleEvaluatorBundle, correlations []*evaluator.CorrelationEvaluator, w *csv.Writer) (scanned, matched int, err error) {
	fd, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer fd.Close()

	chunks, err := evtx.GetChunks(fd)
	if err != nil {
		return 0, 0, err
	}

	base := filepath.Base(path)
	for _, chunk := range chunks {
		records, err := chunk.Parse(0)
		if err != nil {
			// A corrupt chunk shouldn't abort the whole file.
			fmt.Fprintf(os.Stderr, "warning: %s: chunk parse error: %v\n", base, err)
			continue
		}
		for _, record := range records {
			evtx.NormalizeEventData(record.Event)
			event := flattenEvent(record.Event)
			scanned++

			// Use the real EventRecordID from the event's System block; the parser's
			// per-chunk Header.RecordID is only a chunk-local index, not the global
			// record number, so fall back to it only when System is missing it.
			recordID := field(event, "EventRecordID")
			if recordID == "" {
				recordID = fmt.Sprint(record.Header.RecordID)
			}
			rows, err := matchEvent(ctx, event, base, recordID, bundle, correlations)
			if err != nil {
				return scanned, matched, err
			}
			for _, row := range rows {
				if err := w.Write(row); err != nil {
					return scanned, matched, err
				}
				matched++
			}
		}
	}
	return scanned, matched, nil
}

// matchEvent evaluates a single flattened event against every rule and returns
// one CSV row per match.
func matchEvent(ctx context.Context, event map[string]interface{}, sourceFile, recordID string, bundle evaluator.RuleEvaluatorBundle, correlations []*evaluator.CorrelationEvaluator) ([][]string, error) {
	var rows [][]string
	// Window aggregation/correlation by the event's own timestamp (correct for
	// historical replay) rather than wall-clock arrival time.
	if t, ok := eventTimeValue(event); ok {
		ctx = evaluator.WithEventTime(ctx, t)
	}
	eventJSON := toJSON(event)
	eventChannel := field(event, "Channel")
	common := func() []string {
		return []string{
			eventTimestamp(event), sourceFile, recordID,
			field(event, "Computer"), eventChannel, field(event, "EventID"),
		}
	}

	results, err := bundle.Matches(ctx, event)
	if err != nil {
		return nil, err
	}
	for _, res := range results {
		if !res.Match {
			continue
		}
		// Channel filter: skip a rule whose logsource targets a different channel
		// than this event's (mirrors Hayabusa, and avoids cross-channel matches).
		if !ruleAppliesToChannel(res.Rule.Logsource, eventChannel) {
			continue
		}
		row := append(common(),
			res.Rule.ID, res.Rule.Title, res.Rule.Level, strings.Join(res.Rule.Tags, ";"), eventJSON)
		rows = append(rows, row)
	}

	for _, ce := range correlations {
		res, err := ce.Matches(ctx, event)
		if err != nil {
			return nil, err
		}
		if !res.Match {
			continue
		}
		row := append(common(),
			ce.Rule.ID, ce.Rule.Title, ce.Rule.Level, strings.Join(ce.Rule.Tags, ";"), eventJSON)
		rows = append(rows, row)
	}
	return rows, nil
}

// flattenEvent converts the nested evtx event structure into the flat
// field=>value map that Sigma Windows rules expect. The System block is mapped
// to the conventional names (EventID, Provider_Name, Channel, ...) and the
// EventData/UserData fields are lifted to the top level.
func flattenEvent(raw interface{}) map[string]interface{} {
	out := map[string]interface{}{}
	root, ok := raw.(*ordereddict.Dict)
	if !ok {
		return out
	}
	inner, ok := root.Get("Event")
	if !ok {
		return out
	}
	event, ok := inner.(*ordereddict.Dict)
	if !ok {
		return out
	}

	if sys, ok := getDict(event, "System"); ok {
		flattenSystem(sys, out)
	}
	if ed, ok := getDict(event, "EventData"); ok {
		mergeLeaves(ed, out)
	}
	if ud, ok := getDict(event, "UserData"); ok {
		mergeLeaves(ud, out)
	}
	return out
}

func flattenSystem(sys *ordereddict.Dict, out map[string]interface{}) {
	if prov, ok := getDict(sys, "Provider"); ok {
		if name, ok := prov.Get("Name"); ok {
			out["Provider_Name"] = name
		}
	}
	// EventID is usually {"Value": <id>} but can be a bare scalar.
	if eid, ok := sys.Get("EventID"); ok {
		if d, ok := eid.(*ordereddict.Dict); ok {
			if v, ok := d.Get("Value"); ok {
				out["EventID"] = v
			}
		} else {
			out["EventID"] = eid
		}
	}
	for _, k := range []string{"Channel", "Computer", "Level", "Task", "Opcode", "Version", "EventRecordID", "Keywords"} {
		if v, ok := sys.Get(k); ok {
			out[k] = v
		}
	}
	if tc, ok := getDict(sys, "TimeCreated"); ok {
		if st, ok := tc.Get("SystemTime"); ok {
			out["TimeCreated"] = st
		}
	}
	if exec, ok := getDict(sys, "Execution"); ok {
		if pid, ok := exec.Get("ProcessID"); ok {
			out["ProcessID"] = pid
		}
		if tid, ok := exec.Get("ThreadID"); ok {
			out["ThreadID"] = tid
		}
	}
}

// mergeLeaves lifts the scalar leaves of d into out. Nested dicts (e.g. the
// single wrapper element inside UserData) are descended into so their fields
// also land at the top level, matching how Sigma rules reference them.
func mergeLeaves(d *ordereddict.Dict, out map[string]interface{}) {
	for _, k := range d.Keys() {
		v, _ := d.Get(k)
		if sub, ok := v.(*ordereddict.Dict); ok {
			mergeLeaves(sub, out)
		} else {
			out[k] = normalizeEventValue(v)
		}
	}
}

func getDict(d *ordereddict.Dict, key string) (*ordereddict.Dict, bool) {
	v, ok := d.Get(key)
	if !ok {
		return nil, false
	}
	sub, ok := v.(*ordereddict.Dict)
	return sub, ok
}

// eventTimestamp formats System/TimeCreated/SystemTime (float Unix seconds) as
// RFC3339. Returns "" if absent.
func eventTimestamp(event map[string]interface{}) string {
	v, ok := event["TimeCreated"]
	if !ok {
		return ""
	}
	f, ok := v.(float64)
	if !ok {
		return fmt.Sprint(v)
	}
	sec := int64(f)
	nsec := int64((f - float64(sec)) * 1e9)
	return time.Unix(sec, nsec).UTC().Format(time.RFC3339Nano)
}

// eventTimeValue returns the event's TimeCreated as a time.Time (UTC), used to
// window aggregation/correlation by event time. Returns ok=false if absent or not
// a numeric Unix timestamp.
func eventTimeValue(event map[string]interface{}) (time.Time, bool) {
	v, ok := event["TimeCreated"]
	if !ok {
		return time.Time{}, false
	}
	f, ok := v.(float64)
	if !ok {
		return time.Time{}, false
	}
	sec := int64(f)
	return time.Unix(sec, int64((f-float64(sec))*1e9)).UTC(), true
}

func field(event map[string]interface{}, key string) string {
	if v, ok := event[key]; ok {
		return fmt.Sprint(v)
	}
	return ""
}

func toJSON(event map[string]interface{}) string {
	b, err := json.Marshal(event)
	if err != nil {
		return ""
	}
	return string(b)
}

func hasAggregation(rules []sigma.Rule) bool {
	for _, r := range rules {
		for _, c := range r.Detection.Conditions {
			if c.Aggregation != nil {
				return true
			}
		}
	}
	return false
}

var yamlDocSep = regexp.MustCompile(`(?m)^---[ \t]*$`)

// loadRules reads every .yml/.yaml file under path (or path itself if it is a
// file) and parses each YAML document into a Sigma rule. Files that fail to
// parse are reported and skipped rather than aborting the run.
func loadRules(path string) ([]sigma.Rule, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	var files []string
	if info.IsDir() {
		err = filepath.WalkDir(path, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if !d.IsDir() && (strings.HasSuffix(p, ".yml") || strings.HasSuffix(p, ".yaml")) {
				files = append(files, p)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
		sort.Strings(files)
	} else {
		files = []string{path}
	}

	var rules []sigma.Rule
	for _, f := range files {
		contents, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", f, err)
			continue
		}
		for _, doc := range splitYAMLDocs(contents) {
			if strings.TrimSpace(string(doc)) == "" {
				continue
			}
			rule, err := sigma.ParseRule(doc)
			if err != nil {
				fmt.Fprintf(os.Stderr, "warning: %s: skipping (parse error: %v)\n", f, err)
				continue
			}
			// A document with neither detection nor correlation is most likely a
			// config file accidentally living among the rules; skip it quietly.
			if len(rule.Detection.Searches) == 0 && rule.Correlation == nil {
				continue
			}
			rules = append(rules, rule)
		}
	}
	return rules, nil
}

func splitYAMLDocs(contents []byte) [][]byte {
	parts := yamlDocSep.Split(string(contents), -1)
	docs := make([][]byte, 0, len(parts))
	for _, p := range parts {
		docs = append(docs, []byte(p))
	}
	return docs
}
