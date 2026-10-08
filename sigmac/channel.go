package main

import (
	"strings"

	"github.com/doracpphp/sigma-go"
	"github.com/doracpphp/sigma-go/evaluator"
)

// channelFilterEnabled gates the logsource filter (channel, event ID and
// product scoping); set from the -channel-filter flag.
var channelFilterEnabled = true

// serviceChannels maps a Sigma Windows logsource `service` to the evtx Channel(s)
// it targets. Like Hayabusa's channel filter, a rule is only applied to events
// from a matching channel, which avoids a rule meant for one log matching events
// from another. Services not listed here impose no channel restriction.
var serviceChannels = map[string][]string{
	"security":                             {"Security"},
	"system":                               {"System"},
	"application":                          {"Application"},
	"sysmon":                               {"Microsoft-Windows-Sysmon/Operational"},
	"powershell":                           {"Microsoft-Windows-PowerShell/Operational"},
	"powershell-classic":                   {"Windows PowerShell"},
	"taskscheduler":                        {"Microsoft-Windows-TaskScheduler/Operational"},
	"wmi":                                  {"Microsoft-Windows-WMI-Activity/Operational"},
	"windefend":                            {"Microsoft-Windows-Windows Defender/Operational"},
	"dns-server":                           {"DNS Server"},
	"dns-server-audit":                     {"Microsoft-Windows-DNS-Server/Audit"},
	"firewall-as":                          {"Microsoft-Windows-Windows Firewall With Advanced Security/Firewall"},
	"bits-client":                          {"Microsoft-Windows-Bits-Client/Operational"},
	"ntlm":                                 {"Microsoft-Windows-NTLM/Operational"},
	"smbclient-security":                   {"Microsoft-Windows-SmbClient/Security"},
	"ldap_debug":                           {"Microsoft-Windows-LDAP-Client/Debug"},
	"codeintegrity-operational":            {"Microsoft-Windows-CodeIntegrity/Operational"},
	"printservice-admin":                   {"Microsoft-Windows-PrintService/Admin"},
	"printservice-operational":             {"Microsoft-Windows-PrintService/Operational"},
	"terminalservices-localsessionmanager": {"Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"},
	"msexchange-management":                {"MSExchange Management"},
	"appxdeployment-server":                {"Microsoft-Windows-AppXDeploymentServer/Operational"},
	"shell-core":                           {"Microsoft-Windows-Shell-Core/Operational"},
	"openssh":                              {"OpenSSH/Operational"},
	"security-mitigations":                 {"Microsoft-Windows-Security-Mitigations/Kernel Mode", "Microsoft-Windows-Security-Mitigations/User Mode"},
	"applocker": {
		"Microsoft-Windows-AppLocker/EXE and DLL",
		"Microsoft-Windows-AppLocker/MSI and Script",
		"Microsoft-Windows-AppLocker/Packaged app-Deployment",
		"Microsoft-Windows-AppLocker/Packaged app-Execution",
	},
}

// logScope is one evtx channel a rule applies to, optionally narrowed to a set
// of event IDs (nil = every event in the channel).
type logScope struct {
	channel  string
	eventIDs []string
}

const sysmonChannel = "Microsoft-Windows-Sysmon/Operational"

func sysmon(eventIDs ...string) []logScope {
	return []logScope{{channel: sysmonChannel, eventIDs: eventIDs}}
}

// categoryScopes maps a Sigma Windows logsource `category` to the evtx
// channel(s) and event ID(s) that produce it. The event IDs matter as much as
// the channel: Sysmon writes every category to one channel, and without them a
// process_creation rule (say `Image|endswith: '\cmd.exe'`) would also fire on
// network connections, image loads and file events of that process. The Sysmon
// IDs follow pySigma's sysmon pipeline; process_creation also covers Security
// 4688. Categories not listed impose no restriction.
var categoryScopes = map[string][]logScope{
	"process_creation": {
		{channel: sysmonChannel, eventIDs: []string{"1"}},
		{channel: "Security", eventIDs: []string{"4688"}},
	},
	"file_change":              sysmon("2"),
	"network_connection":       sysmon("3"),
	"sysmon_status":            sysmon("4", "16"),
	"process_termination":      sysmon("5"),
	"driver_load":              sysmon("6"),
	"image_load":               sysmon("7"),
	"create_remote_thread":     sysmon("8"),
	"raw_access_thread":        sysmon("9"),
	"process_access":           sysmon("10"),
	"file_event":               sysmon("11"),
	"registry_add":             sysmon("12"),
	"registry_delete":          sysmon("12"),
	"registry_set":             sysmon("13"),
	"registry_rename":          sysmon("14"),
	"registry_event":           sysmon("12", "13", "14"),
	"create_stream_hash":       sysmon("15"),
	"pipe_created":             sysmon("17", "18"),
	"wmi_event":                sysmon("19", "20", "21"),
	"dns_query":                sysmon("22"),
	"file_delete":              sysmon("23", "26"),
	"clipboard_capture":        sysmon("24"),
	"process_tampering":        sysmon("25"),
	"file_delete_detected":     sysmon("26"),
	"file_block_executable":    sysmon("27"),
	"file_block_shredding":     sysmon("28"),
	"file_executable_detected": sysmon("29"),
	"file_block":               sysmon("27", "28"),
	"sysmon_error":             sysmon("255"),
	// PowerShell 7 logs script blocks / module logging to its own channel with the
	// same event IDs.
	"ps_script": {
		{channel: "Microsoft-Windows-PowerShell/Operational", eventIDs: []string{"4104"}},
		{channel: "PowerShellCore/Operational", eventIDs: []string{"4104"}},
	},
	"ps_module": {
		{channel: "Microsoft-Windows-PowerShell/Operational", eventIDs: []string{"4103"}},
		{channel: "PowerShellCore/Operational", eventIDs: []string{"4103"}},
	},
	"ps_classic_start":          {{channel: "Windows PowerShell", eventIDs: []string{"400"}}},
	"ps_classic_provider_start": {{channel: "Windows PowerShell", eventIDs: []string{"600"}}},
	"ps_classic_script":         {{channel: "Windows PowerShell", eventIDs: []string{"800"}}},
}

// ruleScopes returns the channels (and event IDs) a rule's logsource targets,
// or nil if the logsource imposes no known restriction (in which case the rule
// applies to every event). `service` is more specific than `category`.
func ruleScopes(ls sigma.Logsource) []logScope {
	if ls.Service != "" {
		if chans, ok := serviceChannels[strings.ToLower(ls.Service)]; ok {
			scopes := make([]logScope, len(chans))
			for i, c := range chans {
				scopes[i] = logScope{channel: c}
			}
			return scopes
		}
	}
	if ls.Category != "" {
		if scopes, ok := categoryScopes[strings.ToLower(ls.Category)]; ok {
			return scopes
		}
	}
	return nil
}

// ruleChannels returns just the channel names of ruleScopes.
func ruleChannels(ls sigma.Logsource) []string {
	scopes := ruleScopes(ls)
	if scopes == nil {
		return nil
	}
	var chans []string
	for _, s := range scopes {
		if !containsFold(chans, s.channel) {
			chans = append(chans, s.channel)
		}
	}
	return chans
}

// scopeKey identifies a scope set, for grouping rules that share one.
func scopeKey(scopes []logScope) string {
	var b strings.Builder
	for _, s := range scopes {
		b.WriteString(strings.ToLower(s.channel))
		b.WriteByte(0)
		b.WriteString(strings.Join(s.eventIDs, ","))
		b.WriteByte(0)
	}
	return b.String()
}

// scopeApplies reports whether rules restricted to scopes should be evaluated
// against an event from eventChannel with eventID. It returns true (don't
// filter) when the filter is disabled or there is no restriction, and treats a
// missing channel or event ID as unknown rather than as a mismatch; it only
// excludes when the restriction is known and doesn't match.
func scopeApplies(scopes []logScope, eventChannel, eventID string) bool {
	if !channelFilterEnabled || eventChannel == "" || len(scopes) == 0 {
		return true
	}
	for _, s := range scopes {
		if !strings.EqualFold(s.channel, eventChannel) {
			continue
		}
		if len(s.eventIDs) == 0 || eventID == "" {
			return true
		}
		for _, id := range s.eventIDs {
			if id == eventID {
				return true
			}
		}
	}
	return false
}

// channelApplies is scopeApplies for a bare channel list (no event IDs).
func channelApplies(chans []string, eventChannel string) bool {
	scopes := make([]logScope, len(chans))
	for i, c := range chans {
		scopes[i] = logScope{channel: c}
	}
	return scopeApplies(scopes, eventChannel, "")
}

// ruleAppliesToEvent reports whether a rule with the given logsource should be
// evaluated against an event from eventChannel with eventID.
func ruleAppliesToEvent(ls sigma.Logsource, eventChannel, eventID string) bool {
	return scopeApplies(ruleScopes(ls), eventChannel, eventID)
}

// logsourceFilter is the evaluator.WithEventFilter used for the rules a
// correlation evaluates internally, so they get the same channel/event ID
// scoping as the bundled detection rules.
func logsourceFilter(rule sigma.Rule, event evaluator.Event) bool {
	m, ok := event.(map[string]interface{})
	if !ok {
		return true
	}
	return ruleAppliesToEvent(rule.Logsource, field(m, "Channel"), field(m, "EventID"))
}

// targetsWindows reports whether a rule can apply to Windows event logs: its
// logsource product is windows or unset. Rules for other products (linux,
// macos, cloud, ...) reuse field names such as Image and CommandLine, so
// evaluating them against evtx events only produces false positives.
func targetsWindows(ls sigma.Logsource) bool {
	return ls.Product == "" || strings.EqualFold(ls.Product, "windows")
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

// correlationChannels returns the channels an event must come from to be
// relevant to the given correlation rule: the union of the channels of every
// rule it references, transitively through chained correlations. It returns
// nil (no restriction) if any referenced rule is unrestricted or can't be
// resolved, so filtering stays conservative.
func correlationChannels(rule sigma.Rule, all []sigma.Rule) []string {
	lookup := map[string]sigma.Rule{}
	for _, r := range all {
		if r.Name != "" {
			lookup[r.Name] = r
		}
		if r.ID != "" {
			lookup[r.ID] = r
		}
	}

	var union []string
	unrestricted := false
	seen := map[string]bool{}
	var visit func(r sigma.Rule)
	visit = func(r sigma.Rule) {
		key := r.Name + "\x00" + r.ID
		if seen[key] || unrestricted {
			return
		}
		seen[key] = true
		if r.Correlation == nil {
			chans := ruleChannels(r.Logsource)
			if len(chans) == 0 {
				unrestricted = true
				return
			}
			for _, c := range chans {
				if !containsFold(union, c) {
					union = append(union, c)
				}
			}
			return
		}
		for _, ref := range r.Correlation.Rules {
			referenced, ok := lookup[ref]
			if !ok {
				unrestricted = true
				return
			}
			visit(referenced)
		}
	}
	visit(rule)
	if unrestricted {
		return nil
	}
	return union
}
