package main

import (
	"fmt"
	"strings"
)

// hexFields are the Windows event fields whose schema type is HexInt32/HexInt64.
// Event Viewer and the event XML render them as 0x-prefixed hex
// (`Status: 0xc000006d`), and Sigma rules are written against that form, but the
// evtx parser hands them over as plain integers (3221225581). The schema type
// isn't exposed by the parser (HexInt32 and UInt32 both arrive as uint32), so
// the fields are identified by name.
var hexFields = map[string]bool{
	"Status":               true, // 4625, 4768, 4769, 4771, 4776, ...
	"SubStatus":            true, // 4625
	"TicketOptions":        true, // 4768, 4769, 4770
	"TicketEncryptionType": true, // 4768, 4769
	"AccessMask":           true, // 4656, 4663, 5145, ...
	"GrantedAccess":        true, // Sysmon 10
	"SubjectLogonId":       true,
	"TargetLogonId":        true,
	"TargetLinkedLogonId":  true,
	"LogonId":              true,
	"Keywords":             true, // System/Keywords
}

// normalizeEventValue normalizes a flattened event value the way Event Viewer
// presents Windows event fields, so that Sigma rules
// (written against the human-readable form) match:
//   - leading/trailing whitespace is removed, since Windows pads many Security
//     fields (e.g. LogonProcessName is "NtLmSsp " while rules look for "NtLmSsp");
//   - integer values of hex-typed fields (see hexFields) are rendered as
//     lowercase 0x-prefixed hex, as in the event XML.
//
// Other values pass through unchanged.
//
// Note: %%NNNN message-table codes (e.g. "%%1833") are deliberately NOT resolved.
// Sigma rules for evtx compare these verbatim, so resolving them only causes
// divergence (rules written against raw codes stop matching, while rules written
// against resolved text match events other evtx tools don't flag).
func normalizeEventValue(key string, v interface{}) interface{} {
	switch val := v.(type) {
	case string:
		return strings.TrimSpace(val)
	case uint8, uint16, uint32, uint64:
		if hexFields[key] {
			return fmt.Sprintf("0x%x", val)
		}
	}
	return v
}
