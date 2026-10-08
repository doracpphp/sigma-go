package main

import "testing"

func TestNormalizeEventValue(t *testing.T) {
	cases := []struct {
		name string
		key  string
		in   interface{}
		want interface{}
	}{
		{"trailing space trimmed", "LogonProcessName", "NtLmSsp ", "NtLmSsp"},
		{"leading and trailing trimmed", "x", "  User32  ", "User32"},
		{"no change needed", "Image", "cmd.exe", "cmd.exe"},
		{"non-string passes through", "LogonType", 4624, 4624},
		{"decimal-typed integer stays an integer", "LogonType", uint32(3), uint32(3)},
		{"empty string", "x", "", ""},
		{"only whitespace becomes empty", "x", "   ", ""},
		{"resource codes are NOT resolved (left verbatim)", "x", "%%1833", "%%1833"},
		{"resource code with padding is only trimmed", "x", "  %%1833  ", "%%1833"},
		// The evtx parser returns HexInt32/HexInt64 fields as integers; rules and
		// Event Viewer use the 0x form.
		{"HexInt32 status rendered as hex", "SubStatus", uint32(3221225578), "0xc000006a"},
		{"HexInt32 encryption type rendered as hex", "TicketEncryptionType", uint32(0x17), "0x17"},
		{"HexInt64 logon ID rendered as hex", "TargetLogonId", uint64(999), "0x3e7"},
		{"hex field already a string is only trimmed", "Status", " 0x0 ", "0x0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeEventValue(tc.key, tc.in)
			if got != tc.want {
				t.Errorf("normalizeEventValue(%q, %#v) = %#v, want %#v", tc.key, tc.in, got, tc.want)
			}
		})
	}
}
