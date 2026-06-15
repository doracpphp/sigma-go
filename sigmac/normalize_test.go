package main

import "testing"

func TestNormalizeEventValue(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
		want interface{}
	}{
		{"trailing space trimmed", "NtLmSsp ", "NtLmSsp"},
		{"leading and trailing trimmed", "  User32  ", "User32"},
		{"no change needed", "cmd.exe", "cmd.exe"},
		{"non-string passes through", 4624, 4624},
		{"empty string", "", ""},
		{"only whitespace becomes empty", "   ", ""},
		{"resource codes are NOT resolved (left verbatim)", "%%1833", "%%1833"},
		{"resource code with padding is only trimmed", "  %%1833  ", "%%1833"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := normalizeEventValue(tc.in)
			if got != tc.want {
				t.Errorf("normalizeEventValue(%#v) = %#v, want %#v", tc.in, got, tc.want)
			}
		})
	}
}
