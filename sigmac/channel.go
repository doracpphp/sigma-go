package main

import (
	"strings"

	"github.com/doracpphp/sigma-go"
)

// channelFilterEnabled gates the channel filter; set from the -channel-filter flag.
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

// categoryChannels maps a Sigma Windows logsource `category` to its evtx
// Channel(s). Most categories are Sysmon-only; process_creation also covers
// Security 4688. Categories not listed impose no channel restriction.
var categoryChannels = map[string][]string{
	"process_creation":          {"Microsoft-Windows-Sysmon/Operational", "Security"},
	"network_connection":        {"Microsoft-Windows-Sysmon/Operational"},
	"image_load":                {"Microsoft-Windows-Sysmon/Operational"},
	"file_event":                {"Microsoft-Windows-Sysmon/Operational"},
	"file_change":               {"Microsoft-Windows-Sysmon/Operational"},
	"file_delete":               {"Microsoft-Windows-Sysmon/Operational"},
	"file_rename":               {"Microsoft-Windows-Sysmon/Operational"},
	"file_block":                {"Microsoft-Windows-Sysmon/Operational"},
	"file_executable_detected":  {"Microsoft-Windows-Sysmon/Operational"},
	"registry_event":            {"Microsoft-Windows-Sysmon/Operational"},
	"registry_add":              {"Microsoft-Windows-Sysmon/Operational"},
	"registry_delete":           {"Microsoft-Windows-Sysmon/Operational"},
	"registry_set":              {"Microsoft-Windows-Sysmon/Operational"},
	"registry_rename":           {"Microsoft-Windows-Sysmon/Operational"},
	"process_access":            {"Microsoft-Windows-Sysmon/Operational"},
	"dns_query":                 {"Microsoft-Windows-Sysmon/Operational"},
	"pipe_created":              {"Microsoft-Windows-Sysmon/Operational"},
	"wmi_event":                 {"Microsoft-Windows-Sysmon/Operational"},
	"driver_load":               {"Microsoft-Windows-Sysmon/Operational"},
	"create_remote_thread":      {"Microsoft-Windows-Sysmon/Operational"},
	"raw_access_thread":         {"Microsoft-Windows-Sysmon/Operational"},
	"create_stream_hash":        {"Microsoft-Windows-Sysmon/Operational"},
	"clipboard_capture":         {"Microsoft-Windows-Sysmon/Operational"},
	"process_tampering":         {"Microsoft-Windows-Sysmon/Operational"},
	"sysmon_status":             {"Microsoft-Windows-Sysmon/Operational"},
	"sysmon_error":              {"Microsoft-Windows-Sysmon/Operational"},
	"ps_script":                 {"Microsoft-Windows-PowerShell/Operational"},
	"ps_module":                 {"Microsoft-Windows-PowerShell/Operational"},
	"ps_classic_start":          {"Windows PowerShell"},
	"ps_classic_provider_start": {"Windows PowerShell"},
	"ps_classic_script":         {"Windows PowerShell"},
}

// ruleChannels returns the evtx channels a rule's logsource targets, or nil if the
// logsource imposes no known channel restriction (in which case the rule applies
// to events from any channel). `service` is more specific than `category`.
func ruleChannels(ls sigma.Logsource) []string {
	if ls.Service != "" {
		if chans, ok := serviceChannels[strings.ToLower(ls.Service)]; ok {
			return chans
		}
	}
	if ls.Category != "" {
		if chans, ok := categoryChannels[strings.ToLower(ls.Category)]; ok {
			return chans
		}
	}
	return nil
}

// channelApplies reports whether rules restricted to chans should be evaluated
// against an event from eventChannel. It returns true (don't filter) when the
// filter is disabled, there is no channel restriction, or the event has no
// channel; it only excludes when the restriction is known and doesn't match.
func channelApplies(chans []string, eventChannel string) bool {
	if !channelFilterEnabled || eventChannel == "" || len(chans) == 0 {
		return true
	}
	for _, c := range chans {
		if strings.EqualFold(c, eventChannel) {
			return true
		}
	}
	return false
}

// ruleAppliesToChannel reports whether a rule with the given logsource should be
// evaluated against an event from eventChannel.
func ruleAppliesToChannel(ls sigma.Logsource, eventChannel string) bool {
	return channelApplies(ruleChannels(ls), eventChannel)
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
		next:
			for _, c := range chans {
				for _, u := range union {
					if strings.EqualFold(u, c) {
						continue next
					}
				}
				union = append(union, c)
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
