package main

import "strings"

// normalizeEventValue normalizes a flattened event value the way tools such as
// Hayabusa and Event Viewer present Windows event fields, so that Sigma rules
// (written against the human-readable form) match: leading/trailing whitespace is
// removed, since Windows pads many Security fields (e.g. LogonProcessName is
// "NtLmSsp " while rules look for "NtLmSsp"). Non-string values pass through
// unchanged.
//
// Note: %%NNNN message-table codes (e.g. "%%1833") are deliberately NOT resolved.
// Hayabusa and raw-evtx matching both compare these verbatim, so resolving them
// only causes divergence (rules written against raw codes stop matching, while
// rules written against resolved text match events the reference tools don't flag).
func normalizeEventValue(v interface{}) interface{} {
	s, ok := v.(string)
	if !ok {
		return v
	}
	return strings.TrimSpace(s)
}
