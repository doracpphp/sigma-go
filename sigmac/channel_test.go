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
		want    bool
	}{
		{"security rule on Security event", sigma.Logsource{Service: "security"}, "Security", true},
		{"security rule on Sysmon event", sigma.Logsource{Service: "security"}, "Microsoft-Windows-Sysmon/Operational", false},
		{"sysmon category on Sysmon event", sigma.Logsource{Category: "process_creation"}, "Microsoft-Windows-Sysmon/Operational", true},
		{"process_creation also matches Security 4688", sigma.Logsource{Category: "process_creation"}, "Security", true},
		{"ps_script on PowerShell channel", sigma.Logsource{Category: "ps_script"}, "Microsoft-Windows-PowerShell/Operational", true},
		{"ps_script on Security event", sigma.Logsource{Category: "ps_script"}, "Security", false},
		{"unmapped service: no restriction", sigma.Logsource{Service: "something-new"}, "Security", true},
		{"product-only rule: no restriction", sigma.Logsource{Product: "windows"}, "Microsoft-Windows-Sysmon/Operational", true},
		{"empty event channel: not filtered", sigma.Logsource{Service: "security"}, "", true},
		{"case-insensitive channel match", sigma.Logsource{Service: "system"}, "system", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ruleAppliesToChannel(tc.ls, tc.channel); got != tc.want {
				t.Errorf("ruleAppliesToChannel(%+v, %q) = %v, want %v", tc.ls, tc.channel, got, tc.want)
			}
		})
	}

	// When disabled, everything applies.
	channelFilterEnabled = false
	if !ruleAppliesToChannel(sigma.Logsource{Service: "security"}, "Microsoft-Windows-Sysmon/Operational") {
		t.Error("with channel filter disabled, the rule should apply regardless of channel")
	}
}
