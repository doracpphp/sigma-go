package main

import (
	"testing"

	"github.com/doracpphp/sigma-go"
)

func TestRuleAppliesToChannel(t *testing.T) {
	defer func() { channelFilterEnabled = true }()
	channelFilterEnabled = true

	cases := []struct {
		name    string
		ls      sigma.Logsource
		channel string
		eventID string
		want    bool
	}{
		{"security rule on Security event", sigma.Logsource{Service: "security"}, "Security", "4625", true},
		{"security rule on Sysmon event", sigma.Logsource{Service: "security"}, "Microsoft-Windows-Sysmon/Operational", "1", false},
		{"sysmon category on Sysmon event", sigma.Logsource{Category: "process_creation"}, "Microsoft-Windows-Sysmon/Operational", "1", true},
		{"process_creation also matches Security 4688", sigma.Logsource{Category: "process_creation"}, "Security", "4688", true},
		{"ps_script on PowerShell channel", sigma.Logsource{Category: "ps_script"}, "Microsoft-Windows-PowerShell/Operational", "4104", true},
		{"ps_script on PowerShell 7 channel", sigma.Logsource{Category: "ps_script"}, "PowerShellCore/Operational", "4104", true},
		{"ps_script on Security event", sigma.Logsource{Category: "ps_script"}, "Security", "4104", false},
		{"unmapped service: no restriction", sigma.Logsource{Service: "something-new"}, "Security", "1", true},
		{"product-only rule: no restriction", sigma.Logsource{Product: "windows"}, "Microsoft-Windows-Sysmon/Operational", "1", true},
		{"empty event channel: not filtered", sigma.Logsource{Service: "security"}, "", "", true},
		{"case-insensitive channel match", sigma.Logsource{Service: "system"}, "system", "7045", true},
		// Sysmon logs every category to one channel; the event ID tells them apart.
		{"process_creation on Sysmon network connection", sigma.Logsource{Category: "process_creation"}, "Microsoft-Windows-Sysmon/Operational", "3", false},
		{"process_creation on Security logon", sigma.Logsource{Category: "process_creation"}, "Security", "4624", false},
		{"registry_event covers 12-14", sigma.Logsource{Category: "registry_event"}, "Microsoft-Windows-Sysmon/Operational", "13", true},
		{"ps_script on module logging event", sigma.Logsource{Category: "ps_script"}, "Microsoft-Windows-PowerShell/Operational", "4103", false},
		{"missing event ID: not filtered", sigma.Logsource{Category: "image_load"}, "Microsoft-Windows-Sysmon/Operational", "", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ruleAppliesToEvent(tc.ls, tc.channel, tc.eventID); got != tc.want {
				t.Errorf("ruleAppliesToEvent(%+v, %q, %q) = %v, want %v", tc.ls, tc.channel, tc.eventID, got, tc.want)
			}
		})
	}

	// When disabled, everything applies.
	channelFilterEnabled = false
	if !ruleAppliesToEvent(sigma.Logsource{Category: "process_creation"}, "Microsoft-Windows-Sysmon/Operational", "3") {
		t.Error("with channel filter disabled, the rule should apply regardless of channel")
	}
}
