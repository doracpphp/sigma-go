# sigma-go ![Build Status](https://github.com/doracpphp/sigma-go/workflows/Go/badge.svg) [![GitHub release](https://img.shields.io/github/release/doracpphp/sigma-go.svg)](https://github.com/doracpphp/sigma-go/releases/latest)
<img src=".github/mascot.png" alt="Mascot" width="150" align="right">

A Go implementation and parser of [Sigma rules](https://github.com/SigmaHQ/sigma). Useful for building your own detection pipelines.

Who's using `sigma-go` in production?
* [Monzo Bank](https://monzo.com/blog/2022/08/05/scaling-our-security-detection-pipeline-with-sigma)
* [Phish Report](https://phish.report/IOK)
* [SysFlow](https://github.com/sysflow-telemetry)

## Usage

This library is designed for you to build your own alert systems.
It exposes the ability to check whether a rule matches a given event but not much else.
It's up to you to use this building block in your own detection pipeline.

A basic usage of this library might look like this:
```go
import (
    sigma "github.com/doracpphp/sigma-go"
    "github.com/doracpphp/sigma-go/evaluator"
)

// You can load/create rules dynamically or use sigmac to load Sigma rule files
rule, _ := sigma.ParseRule(contents)

// Rules need to be wrapped in an evaluator.
// This is also where (if needed) you provide functions implementing the count, max, etc. aggregation functions
e := evaluator.ForRule(rule, options...)

// Get a stream of events from somewhere e.g. audit logs
for event := range events {
    result, err := e.Matches(ctx, event)
    if err != nil {
        // Handle the error (e.g. a malformed rule or unparseable field)
        continue
    }
    if result.Match {
        // Raise your alert here
        newAlert(rule.ID, rule.Description, ...)
    }
}
```

To evaluate many rules against each event efficiently, wrap them in a bundle with
`evaluator.ForRules(rules, options...)`; its `Matches` returns one result per
matching rule.

### Aggregation functions

If your Sigma rules make use of the count, max, min, or any other aggregation function in your conditions then you'll need some extra setup.

When creating an evaluator, you can pass in implementations of each of the aggregation functions:
```go
e := evaluator.ForRule(rule,
    evaluator.CountImplementation(countImplementation),
    evaluator.MaxImplementation(maxImplementation),
)
```

The available option constructors are `CountImplementation`, `CountDistinctImplementation`,
`SumImplementation`, `AverageImplementation`, `MinImplementation`, and `MaxImplementation`.

This repo includes some toy implementations in the `evaluator/aggregators` package
(`aggregators.InMemory(timeframe)` returns a ready-made set of these options) but
for production use cases you'll need to supply your own.

## `sigmac` CLI: scan Windows .evtx logs

This repo ships a small command, `sigmac`, that scans Windows Event Log (`.evtx`)
files against a set of Sigma rules and writes the matching events to CSV. It uses
[Velocidex/evtx](https://github.com/Velocidex/evtx) to parse the logs.

```bash
go build -o sigmac ./sigmac

# Scan one or more evtx files against a rule directory, writing alerts to CSV
sigmac -rules ./rules -out alerts.csv Security.evtx System.evtx
```

Flags:

| Flag | Description |
| --- | --- |
| `-rules` | Sigma rule file or directory (scanned recursively for `.yml`/`.yaml`). Required. |
| `-config` | Optional Sigma config file (field mappings). |
| `-out` | Output CSV path (default: stdout). |
| `-timeframe` | Default sliding window for aggregation rules that don't specify their own (default `1h`). |
| `-channel-filter` | Only evaluate a rule against events from the channel its logsource targets (default `true`; faster and avoids cross-channel matches). |
| `-exclude` | Comma-separated files of rule IDs to skip, in `<uuid> # comment` format. Accepts Hayabusa's `exclude_rules.txt`/`noisy_rules.txt` verbatim. |

Event field values are normalised on ingest the way Event Viewer/Hayabusa present
them — leading/trailing whitespace is trimmed (Windows pads fields like
`LogonProcessName`) — and aggregation/correlation windows are keyed off each
event's own timestamp, so `count()`/correlation results are correct when replaying
historical logs.

Each output row is one `(event, matching rule)` pair with columns:
`timestamp, source_file, record_id, computer, channel, event_id, rule_id, rule_title, rule_level, rule_tags, event_json`.

The evtx event is flattened into the field names Sigma Windows rules expect
(`EventID`, `Provider_Name`, `Channel`, `Computer`, plus the `EventData`/`UserData`
fields), and the full flattened event is preserved as JSON in the last column.

Detection rules (including `count()`/aggregation rules) are evaluated together as
a single bundle; Sigma correlation rules are evaluated separately. Note that
aggregation and correlation windows use wall-clock arrival time, so on historical
replay (processing an old evtx all at once) those windowed results are
approximate — single-event detection rules are unaffected.
