// Command sigmac scans Windows .evtx event logs against a set of Sigma rules
// and writes the matching events to CSV.
//
// Usage:
//
//	sigmac -rules ./rules [-config config.yml] [-out alerts.csv] file1.evtx [file2.evtx ...]
//
// Rules may be a single .yml file or a directory (scanned recursively for
// .yml/.yaml). Detection rules (including count()/aggregation rules) are
// evaluated in bundles grouped by the channel and event IDs their logsource
// targets, so the logsource filter skips whole groups before evaluation; Sigma
// correlation rules are evaluated separately. Aggregation and correlation
// windows use each event's own timestamp, so historical replay is exact.
package main

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Velocidex/ordereddict"
	"gopkg.in/yaml.v3"
	"www.velocidex.com/golang/evtx"

	"github.com/doracpphp/sigma-go"
	"github.com/doracpphp/sigma-go/evaluator"
	"github.com/doracpphp/sigma-go/evaluator/aggregators"
)

func main() {
	flags := flag.NewFlagSet("sigmac", flag.ContinueOnError)
	rulesPath := flags.String("rules", "", "Sigma rule file or directory (required)")
	configPath := flags.String("config", "", "optional Sigma config file (field mappings)")
	outPath := flags.String("out", "", "output CSV file (default: stdout)")
	timeframe := flags.Duration("timeframe", time.Hour, "default sliding window for aggregation rules without their own timeframe")
	channelFilter := flags.Bool("channel-filter", true, "only evaluate a rule against events from the channel and event IDs its logsource targets, and skip rules that don't target Windows event logs (faster, and no cross-channel or cross-category matches)")
	exclude := flags.String("exclude", "", "comma-separated `files` of rule IDs to skip, one \"<uuid>  # comment\" per line")
	flags.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: sigmac -rules <file|dir> [-config c.yml] [-out alerts.csv] <file.evtx> ...")
		fmt.Fprintln(os.Stderr, "  <file.evtx> is one or more .evtx event log files")
		flags.PrintDefaults()
	}

	// Parse flags and positional arguments in any order (Go's flag package
	// otherwise stops at the first positional argument). Everything after a
	// bare `--` is taken verbatim as positional arguments, so filenames that
	// start with a dash work; it is appended after the interleaved positionals
	// so the scan order matches the command line.
	args := os.Args[1:]
	var tail []string
	for i, a := range args {
		if a == "--" {
			tail = args[i+1:]
			args = args[:i]
			break
		}
	}
	var inputs []string
	for len(args) > 0 {
		if err := flags.Parse(args); err != nil {
			os.Exit(2)
		}
		args = flags.Args()
		if len(args) > 0 {
			inputs = append(inputs, args[0])
			args = args[1:]
		}
	}
	inputs = append(inputs, tail...)

	if *rulesPath == "" || len(inputs) == 0 {
		flags.Usage()
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
// lines starting with `#` are ignored.
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

// bundleGroup is a set of detection rules sharing one logsource scope (channels
// and event IDs), evaluated together. The scope filter is applied per group
// before evaluation: an event outside the scope never reaches the group's
// evaluators, so it can't inflate stateful aggregation (count() etc.) state,
// and skipped groups cost nothing.
type bundleGroup struct {
	scopes []logScope // what the group's rules target; nil = no restriction
	bundle evaluator.RuleEvaluatorBundle
}

func buildBundles(rules []sigma.Rule, options ...evaluator.Option) []bundleGroup {
	byKey := map[string][]sigma.Rule{}
	var order []string
	for _, r := range rules {
		k := scopeKey(ruleScopes(r.Logsource))
		if _, ok := byKey[k]; !ok {
			order = append(order, k)
		}
		byKey[k] = append(byKey[k], r)
	}
	groups := make([]bundleGroup, 0, len(order))
	for _, k := range order {
		rs := byKey[k]
		groups = append(groups, bundleGroup{
			scopes: ruleScopes(rs[0].Logsource),
			bundle: evaluator.ForRules(rs, options...),
		})
	}
	return groups
}

// corrEntry pairs a correlation evaluator with the channel restriction derived
// from its referenced rules, so wrong-channel events are skipped before they
// can pollute the correlation's window state.
type corrEntry struct {
	ce       *evaluator.CorrelationEvaluator
	channels []string
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
	if channelFilterEnabled {
		kept := rules[:0]
		skipped := 0
		for _, r := range rules {
			if !targetsWindows(r.Logsource) {
				skipped++
				continue
			}
			kept = append(kept, r)
		}
		rules = kept
		if skipped > 0 {
			fmt.Fprintf(os.Stderr, "skipped %d non-Windows rule(s) (logsource doesn't target Windows event logs)\n", skipped)
		}
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

	// Split detection rules (evaluated together, bundled per channel) from
	// correlation rules (each evaluated against the full rule set it references).
	var detectionRules []sigma.Rule
	var correlationRules []sigma.Rule
	for _, r := range rules {
		if r.Correlation != nil {
			correlationRules = append(correlationRules, r)
		} else {
			detectionRules = append(detectionRules, r)
		}
	}

	// The rules a correlation evaluates internally get the same logsource scoping
	// as the bundled rules, so out-of-scope events can't advance its windows.
	corrOptions := append(append([]evaluator.Option{}, options...), evaluator.WithEventFilter(logsourceFilter))
	var correlations []corrEntry
	for _, r := range correlationRules {
		ce, err := evaluator.ForCorrelation(r, rules, corrOptions...)
		if err != nil {
			fmt.Fprintf(os.Stderr, "skipping correlation rule %q: %v\n", r.Title, err)
			continue
		}
		correlations = append(correlations, corrEntry{ce: ce, channels: correlationChannels(r, rules)})
	}

	// Per the Sigma correlation spec, the rules a correlation references only
	// produce alerts of their own when it sets `generate: true`; by default only
	// the correlation is reported.
	hidden := hiddenByCorrelations(correlations)
	detectionRules = withoutHidden(detectionRules, hidden)
	kept := correlations[:0]
	for _, c := range correlations {
		if !hidden.has(c.ce.Rule) {
			kept = append(kept, c)
		}
	}
	correlations = kept

	groups := buildBundles(detectionRules, options...)

	fmt.Fprintf(os.Stderr, "loaded %d detection rule(s), %d correlation rule(s)\n", len(detectionRules), len(correlations))

	out := os.Stdout
	var outFile *os.File
	if outPath != "" {
		f, err := os.Create(outPath)
		if err != nil {
			return err
		}
		// Safety net for early error returns; the success path closes explicitly
		// below so a close-time write failure isn't silently swallowed.
		defer f.Close()
		outFile = f
		out = f
	}
	w := csv.NewWriter(out)
	header := []string{
		"timestamp", "source_file", "record_id", "computer", "channel", "event_id",
		"rule_id", "rule_title", "rule_level", "rule_tags", "event_json",
	}
	if err := w.Write(header); err != nil {
		return err
	}

	ctx := context.Background()
	var scanned, matched, failed int
	for _, path := range inputs {
		n, m, err := scanFile(ctx, path, groups, correlations, w)
		// scanFile returns partial counts alongside an error; keep them so the
		// summary reflects everything that was actually processed.
		scanned += n
		matched += m
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v\n", path, err)
			failed++
		}
	}
	w.Flush()
	if err := w.Error(); err != nil {
		return err
	}
	if outFile != nil {
		if err := outFile.Close(); err != nil {
			return fmt.Errorf("writing %s: %w", outPath, err)
		}
	}
	fmt.Fprintf(os.Stderr, "scanned %d event(s), wrote %d alert row(s)\n", scanned, matched)
	if failed == len(inputs) {
		return fmt.Errorf("all %d input file(s) failed", failed)
	}
	return nil
}

// ruleRefs is a set of rule references (names and IDs).
type ruleRefs map[string]bool

func (refs ruleRefs) has(r sigma.Rule) bool {
	return (r.Name != "" && refs[r.Name]) || (r.ID != "" && refs[r.ID])
}

// hiddenByCorrelations returns the rules that only exist to feed a correlation:
// referenced by a correlation without `generate: true`, and not by any
// correlation with it.
func hiddenByCorrelations(correlations []corrEntry) ruleRefs {
	hidden, generated := ruleRefs{}, ruleRefs{}
	for _, c := range correlations {
		corr := c.ce.Rule.Correlation
		for _, ref := range corr.Rules {
			if corr.Generate {
				generated[ref] = true
			} else {
				hidden[ref] = true
			}
		}
	}
	for ref := range generated {
		delete(hidden, ref)
	}
	return hidden
}

func withoutHidden(rules []sigma.Rule, hidden ruleRefs) []sigma.Rule {
	if len(hidden) == 0 {
		return rules
	}
	var kept []sigma.Rule
	for _, r := range rules {
		if !hidden.has(r) {
			kept = append(kept, r)
		}
	}
	return kept
}

// scanFile parses one evtx file and writes a CSV row for every (event, matching
// rule) pair. It returns the number of events scanned and alert rows written,
// which are valid (as partial counts) even when err is non-nil.
func scanFile(ctx context.Context, path string, groups []bundleGroup, correlations []corrEntry, w *csv.Writer) (scanned, matched int, err error) {
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
			rows := matchEvent(ctx, event, base, recordID, groups, correlations)
			for _, row := range rows {
				sanitizeCSVRow(row)
				if err := w.Write(row); err != nil {
					return scanned, matched, err
				}
				matched++
			}
		}
	}
	return scanned, matched, nil
}

// warnedOnce deduplicates per-rule evaluation warnings: a broken rule errors on
// every event, and printing the same message millions of times would flood stderr.
var warnedOnce sync.Map

func warnOnce(msg string) {
	if _, loaded := warnedOnce.LoadOrStore(msg, true); !loaded {
		fmt.Fprintln(os.Stderr, "warning:", msg)
	}
}

// matchEvent evaluates a single flattened event against every rule and returns
// one CSV row per match. Rule-evaluation errors (e.g. one malformed rule) are
// reported once and don't stop the scan.
func matchEvent(ctx context.Context, event map[string]interface{}, sourceFile, recordID string, groups []bundleGroup, correlations []corrEntry) [][]string {
	var rows [][]string
	// Window aggregation/correlation by the event's own timestamp (correct for
	// historical replay) rather than wall-clock arrival time.
	if t, ok := eventTimeValue(event); ok {
		ctx = evaluator.WithEventTime(ctx, t)
	}
	eventChannel := field(event, "Channel")
	eventID := field(event, "EventID")
	// Marshal the event lazily: on a realistic scan almost no events match, and
	// JSON-encoding every event would dominate the scan's cost.
	eventJSON := ""
	haveJSON := false
	getJSON := func() string {
		if !haveJSON {
			eventJSON = toJSON(event)
			haveJSON = true
		}
		return eventJSON
	}
	common := func() []string {
		return []string{
			eventTimestamp(event), sourceFile, recordID,
			field(event, "Computer"), eventChannel, field(event, "EventID"),
		}
	}

	for _, g := range groups {
		// Logsource filter: a group whose rules target a
		// different channel or event ID is skipped before evaluation, so its
		// aggregation state never sees this event.
		if !scopeApplies(g.scopes, eventChannel, eventID) {
			continue
		}
		// Matches returns the healthy rules' results even when some rules error.
		results, err := g.bundle.Matches(ctx, event)
		if err != nil {
			warnOnce(err.Error())
		}
		for _, res := range results {
			if !res.Match {
				continue
			}
			row := append(common(),
				res.Rule.ID, res.Rule.Title, res.Rule.Level, strings.Join(res.Rule.Tags, ";"), getJSON())
			rows = append(rows, row)
		}
	}

	for _, c := range correlations {
		// Same pre-evaluation filter for correlations, based on the channels of the
		// rules the correlation references.
		if !channelApplies(c.channels, eventChannel) {
			continue
		}
		res, err := c.ce.Matches(ctx, event)
		if err != nil {
			warnOnce(fmt.Sprintf("correlation rule %q: %v", c.ce.Rule.Title, err))
			continue
		}
		if !res.Match {
			continue
		}
		row := append(common(),
			c.ce.Rule.ID, c.ce.Rule.Title, c.ce.Rule.Level, strings.Join(c.ce.Rule.Tags, ";"), getJSON())
		rows = append(rows, row)
	}
	return rows
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
			out[k] = normalizeEventValue(k, v)
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
//
// Some providers name EventData fields with spaces (Windows Defender writes
// "New Value", "Product Name"), while Sigma rules use the space-free form
// (`NewValue`), so such fields are also exposed under that name unless the
// event has a real field of that name.
func mergeLeaves(d *ordereddict.Dict, out map[string]interface{}) {
	for _, k := range d.Keys() {
		v, _ := d.Get(k)
		if sub, ok := v.(*ordereddict.Dict); ok {
			mergeLeaves(sub, out)
			continue
		}
		val := normalizeEventValue(k, v)
		out[k] = val
		if strings.Contains(k, " ") {
			alias := strings.ReplaceAll(k, " ", "")
			if _, exists := d.Get(alias); !exists {
				out[alias] = val
			}
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
// RFC3339 for the CSV. Returns "" if absent, or the raw value formatted with
// fmt.Sprint if it isn't the numeric timestamp the evtx parser produces.
func eventTimestamp(event map[string]interface{}) string {
	if t, ok := eventTimeValue(event); ok {
		return t.Format(time.RFC3339Nano)
	}
	return field(event, "TimeCreated")
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

// sanitizeCSVRow guards against CSV formula injection: event field values are
// attacker-controlled and a cell beginning with =, +, - or @ (or a stray
// tab/CR) is executed as a formula when the CSV is opened in Excel/LibreOffice.
// Such cells are prefixed with a single quote, the conventional neutralizer.
func sanitizeCSVRow(row []string) {
	for i, cell := range row {
		if cell == "" {
			continue
		}
		switch cell[0] {
		case '=', '+', '-', '@', '\t', '\r':
			row[i] = "'" + cell
		}
	}
}

func toJSON(event map[string]interface{}) string {
	b, err := json.Marshal(event)
	if err != nil {
		return ""
	}
	return string(b)
}

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
				// One unreadable subdirectory shouldn't abort the run; that matches
				// the lenient per-file policy below. An unreadable root still fails.
				if p == path {
					return err
				}
				fmt.Fprintf(os.Stderr, "warning: %s: %v\n", p, err)
				return nil
			}
			if d.IsDir() {
				return nil
			}
			switch strings.ToLower(filepath.Ext(p)) {
			case ".yml", ".yaml":
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
		docs, err := splitYAMLDocs(contents)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: %s: %v (any later documents in this file are skipped)\n", f, err)
		}
		for _, doc := range docs {
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

// splitYAMLDocs splits a (possibly multi-document) YAML stream into its
// individual documents using a real YAML decoder. A regex/line-based split
// gets the edge cases wrong: CRLF separator lines, `--- # comment` separators,
// and `---` lines inside block scalars all mis-split and silently drop rules.
// Each document is re-serialized for the rule parser. On a syntax error the
// documents decoded so far are returned along with the error (the rest of the
// stream can't be recovered).
func splitYAMLDocs(contents []byte) ([][]byte, error) {
	dec := yaml.NewDecoder(bytes.NewReader(contents))
	var docs [][]byte
	for {
		var node yaml.Node
		err := dec.Decode(&node)
		if errors.Is(err, io.EOF) {
			return docs, nil
		}
		if err != nil {
			return docs, fmt.Errorf("splitting YAML documents: %w", err)
		}
		doc, err := yaml.Marshal(&node)
		if err != nil {
			return docs, fmt.Errorf("re-encoding YAML document: %w", err)
		}
		docs = append(docs, doc)
	}
}
