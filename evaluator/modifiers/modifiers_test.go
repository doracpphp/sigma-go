package modifiers

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"math/rand"
	"strings"
	"testing"
)

// base64offset's purpose is to find a string embedded at any byte alignment inside
// a larger Base64 blob. This verifies that guarantee directly: for each leading
// alignment, the secret embedded in a blob is detectable via at least one variant.
func TestBase64Offset(t *testing.T) {
	// Secrets of every length mod 3, so the end-trimming is exercised for each
	// residue (the number of trailing chars to drop depends on len(secret)+offset).
	for _, secret := range []string{"powershell -enc", "ping", "/bin/bash"} {
		expanded, err := base64offset{}.ModifyMulti(secret)
		if err != nil {
			t.Fatal(err)
		}
		if len(expanded) != 3 {
			t.Fatalf("expected 3 base64offset variants, got %d", len(expanded))
		}

		for pad := 0; pad < 6; pad++ {
			blob := strings.Repeat("X", pad) + secret + "YYYY"
			encoded := base64.StdEncoding.EncodeToString([]byte(blob))
			found := false
			for _, v := range expanded {
				if strings.Contains(encoded, v.(string)) {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("secret=%q pad=%d: no base64offset variant detected in %q (variants=%v)", secret, pad, encoded, expanded)
			}
		}
	}
}

// TestBase64OffsetPySigmaParity pins the exact variants to the output of pySigma's
// SigmaBase64OffsetModifier (b64encode(i*b" "+val)[start[i]:end[(len(val)+i)%3]]).
func TestBase64OffsetPySigmaParity(t *testing.T) {
	tests := []struct {
		value string
		want  []string
	}{
		{"ping", []string{"cGluZ", "Bpbm", "waW5n"}},
		{"/bin/bash", []string{"L2Jpbi9iYXNo", "9iaW4vYmFza", "vYmluL2Jhc2"}},
		{"Net.WebClient", []string{"TmV0LldlYkNsaWVud", "5ldC5XZWJDbGllbn", "OZXQuV2ViQ2xpZW50"}},
		{"ab", []string{"YW", "Fi", "hY"}},
	}
	for _, tt := range tests {
		got, err := base64offset{}.ModifyMulti(tt.value)
		if err != nil {
			t.Fatal(err)
		}
		for i, want := range tt.want {
			if got[i].(string) != want {
				t.Errorf("base64offset(%q)[%d] = %q, want %q", tt.value, i, got[i], want)
			}
		}
	}
}

func TestUTF16Modifiers(t *testing.T) {
	// "AB" -> UTF-16-LE: 0x41 0x00 0x42 0x00 ; UTF-16-BE: 0x00 0x41 0x00 0x42
	if got := encodeUTF16("AB", binary.LittleEndian, false); got != "\x41\x00\x42\x00" {
		t.Fatalf("utf16le(AB) = % x", []byte(got))
	}
	if got := encodeUTF16("AB", binary.BigEndian, false); got != "\x00\x41\x00\x42" {
		t.Fatalf("utf16be(AB) = % x", []byte(got))
	}
	// utf16 (with BOM) prepends FF FE (little-endian BOM).
	withBOM, _ := utf16WithBOM{}.Modify("AB")
	if withBOM.(string) != "\xff\xfe\x41\x00\x42\x00" {
		t.Fatalf("utf16(AB) = % x", []byte(withBOM.(string)))
	}
	// `wide` is an alias for utf16le.
	wide, _ := ValueModifiers["wide"].Modify("AB")
	le, _ := ValueModifiers["utf16le"].Modify("AB")
	if wide.(string) != le.(string) {
		t.Fatal("wide should be an alias for utf16le")
	}
}

func TestWindash(t *testing.T) {
	expanded, err := windash{}.ModifyMulti("-foo")
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{"-foo": false, "/foo": false, "–foo": false, "—foo": false, "―foo": false}
	if len(expanded) != len(want) {
		t.Fatalf("expected %d windash variants, got %d: %v", len(want), len(expanded), expanded)
	}
	for _, v := range expanded {
		s := v.(string)
		if _, ok := want[s]; !ok {
			t.Fatalf("unexpected windash variant %q", s)
		}
		want[s] = true
	}
	for s, seen := range want {
		if !seen {
			t.Fatalf("missing windash variant %q", s)
		}
	}

	// A value with no dash yields just itself.
	none, _ := windash{}.ModifyMulti("foo")
	if len(none) != 1 || none[0].(string) != "foo" {
		t.Fatalf("expected single unchanged value, got %v", none)
	}
}

// windash must only expand argument-leading dashes (`\B[-/]\b`), matching
// pySigma. Hyphens inside words are left alone so we don't over-generate variants.
func TestWindashBoundary(t *testing.T) {
	count := func(value string) int {
		expanded, err := windash{}.ModifyMulti(value)
		if err != nil {
			t.Fatal(err)
		}
		return len(expanded)
	}

	// Internal hyphen (`foo-bar`) is not a trigger -> single, unchanged variant.
	got, _ := windash{}.ModifyMulti("foo-bar")
	if len(got) != 1 || got[0].(string) != "foo-bar" {
		t.Fatalf("internal hyphen should not expand, got %v", got)
	}
	// Leading dash and slash are triggers -> 5 variants each.
	if n := count("-foo"); n != len(windashChars) {
		t.Fatalf("`-foo` should expand to %d variants, got %d", len(windashChars), n)
	}
	if n := count("/foo"); n != len(windashChars) {
		t.Fatalf("`/foo` should expand to %d variants, got %d", len(windashChars), n)
	}
	// `-foo-bar`: only the leading dash triggers (the internal one is at a word
	// boundary), so 5 variants, not 25.
	if n := count("-foo-bar"); n != len(windashChars) {
		t.Fatalf("`-foo-bar` should expand only the leading dash (%d variants), got %d", len(windashChars), n)
	}
	// Two argument-leading dashes -> cartesian product of 5x5.
	if n := count("-foo /bar"); n != len(windashChars)*len(windashChars) {
		t.Fatalf("`-foo /bar` should expand to %d variants, got %d", len(windashChars)*len(windashChars), n)
	}
	// An en dash in the original is not a trigger (only `-`/`/` are).
	enDash, _ := windash{}.ModifyMulti("–foo")
	if len(enDash) != 1 {
		t.Fatalf("en dash should not be a trigger, got %v", enDash)
	}
}

func TestRegexFlagModifiers(t *testing.T) {
	cases := []struct {
		name      string
		modifiers []string
		actual    string
		pattern   string
		want      bool
	}{
		{"plain re matches", []string{"re"}, "abcDEF", "abc", true},
		{"plain re is case-sensitive", []string{"re"}, "ABCDEF", "abc", false},
		{"re|i case-insensitive match", []string{"re", "i"}, "ABCDEF", "abc", true},
		{"re|s dot matches newline", []string{"re", "s"}, "a\nb", "a.b", true},
		{"re without s dot excludes newline", []string{"re"}, "a\nb", "a.b", false},
		{"re|m caret matches line start", []string{"re", "m"}, "first\nsecond", "^second", true},
		{"re without m caret only matches string start", []string{"re"}, "first\nsecond", "^second", false},
		{"combined re|i|s", []string{"re", "i", "s"}, "A\nB", "a.b", true},
		// pySigma also accepts the long-form flag names.
		{"re|ignorecase match", []string{"re", "ignorecase"}, "ABCDEF", "abc", true},
		{"re|dotall dot matches newline", []string{"re", "dotall"}, "a\nb", "a.b", true},
		{"re|multiline caret matches line start", []string{"re", "multiline"}, "first\nsecond", "^second", true},
		{"combined re|ignorecase|dotall", []string{"re", "ignorecase", "dotall"}, "A\nB", "a.b", true},
		{"mixed short and long re|i|dotall", []string{"re", "i", "dotall"}, "A\nB", "a.b", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cmp, err := GetComparator("", nil, tc.modifiers...)
			if err != nil {
				t.Fatal(err)
			}
			got, err := cmp(tc.actual, tc.pattern)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("got %v want %v", got, tc.want)
			}
		})
	}

	// A flag character not following `re` is still an unknown modifier.
	if _, err := GetComparator("", nil, "i"); err == nil {
		t.Fatal("expected error for bare 'i' modifier not following 're'")
	}
}

// Exercise the full value-modifier chain through GetComparator, including the
// multi-value expansion path used by windash and base64offset.
func TestGetComparatorMultiValueChain(t *testing.T) {
	// CommandLine|windash|contains: the event spoofs the dash with a forward slash.
	cmp, err := GetComparator("", nil, "windash", "contains")
	if err != nil {
		t.Fatal(err)
	}
	matched, err := cmp("program.exe /foo bar", "-foo")
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatal("windash|contains should match /foo against rule value -foo")
	}

	// CommandLine|utf16le|base64offset|contains: classic detection of a wide-encoded
	// string inside a Base64 blob (e.g. PowerShell -EncodedCommand).
	cmp2, err := GetComparator("", nil, "utf16le", "base64offset", "contains")
	if err != nil {
		t.Fatal(err)
	}
	secret := "Net.WebClient"
	wideBlob := encodeUTF16("XX"+secret+"YY", binary.LittleEndian, false) // secret not 3-byte aligned
	event := base64.StdEncoding.EncodeToString([]byte(wideBlob))
	matched, err = cmp2(event, secret)
	if err != nil {
		t.Fatal(err)
	}
	if !matched {
		t.Fatalf("utf16le|base64offset|contains should find %q inside %q", secret, event)
	}
}

// Real-world SigmaHQ rules write the comparator before value modifiers
// (e.g. `ImagePath|contains|windash`) as well as after; both orders must work
// and mean the same thing.
func TestComparatorBeforeValueModifier(t *testing.T) {
	for _, mods := range [][]string{
		{"contains", "windash"},
		{"windash", "contains"},
	} {
		comparator, err := GetComparator("ImagePath", nil, mods...)
		if err != nil {
			t.Fatalf("%v: %v", mods, err)
		}
		matched, err := comparator(`sc config /start= disabled`, `-start=`)
		if err != nil {
			t.Fatal(err)
		}
		if !matched {
			t.Errorf("%v: windash variant of '-start=' should contains-match '/start='", mods)
		}
	}

	// ... but two comparators in one chain are still rejected.
	if _, err := GetComparator("f", nil, "contains", "startswith"); err == nil {
		t.Error("expected an error for two comparator modifiers")
	}
}

func Test_compareNumeric(t *testing.T) {
	tests := []struct {
		left       interface{}
		right      interface{}
		wantGt     bool
		wantGte    bool
		wantLt     bool
		wantLte    bool
		shouldFail bool
	}{
		{1, 2, false, false, true, true, false},
		{1.1, 1.2, false, false, true, true, false},
		{1, 1.2, false, false, true, true, false},
		{1.1, 2, false, false, true, true, false},
		{1, "2", false, false, true, true, false},
		{"1.1", 1.2, false, false, true, true, false},
		{"1.1", 1.1, false, true, false, true, false},

		// The function panics if it's interfaces are nil, this happens if it doesn't find the field in the event and it's compared to a int or float
		{nil, 2, true, false, false, false, true},
		{nil, nil, true, false, false, false, true},
		{2, nil, true, false, false, false, true},
		// If we pass anything (like an ip address) other than an int or float, the functions recurses until it stack overflows
		{"127.0.0.1", "127.0.0.1", true, false, false, false, true},
		{"127.0.0.1", 0.2, true, false, false, false, true},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s", tt.left, tt.right), func(t *testing.T) {
			gotGt, gotGte, gotLt, gotLte, err := compareNumeric(tt.left, tt.right)
			if err != nil {
				if !tt.shouldFail {
					t.Errorf("compareNumeric() error = %v", err)
					return
				} else {
					return
				}
			}
			if gotGt != tt.wantGt {
				t.Errorf("compareNumeric() gotGt = %v, want %v", gotGt, tt.wantGt)
			}
			if gotGte != tt.wantGte {
				t.Errorf("compareNumeric() gotGte = %v, want %v", gotGte, tt.wantGte)
			}
			if gotLt != tt.wantLt {
				t.Errorf("compareNumeric() gotLt = %v, want %v", gotLt, tt.wantLt)
			}
			if gotLte != tt.wantLte {
				t.Errorf("compareNumeric() gotLte = %v, want %v", gotLte, tt.wantLte)
			}
		})
	}
}

func BenchmarkContains(b *testing.B) {
	needle := "abcdefg"

	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	haystack := make([]rune, 1_000_000)
	for i := range haystack {
		haystack[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	haystackString := string(haystack)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := contains{}.Matches(string(haystackString), needle)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkContainsCS(b *testing.B) {
	needle := "abcdefg"

	var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
	haystack := make([]rune, 1_000_000)
	for i := range haystack {
		haystack[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	haystackString := string(haystack)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := containsCS{}.Matches(string(haystackString), needle)
		if err != nil {
			b.Fatal(err)
		}
	}
}
