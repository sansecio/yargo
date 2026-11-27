package scanner

import (
	"reflect"
	"testing"
)

func TestWideString(t *testing.T) {
	tests := []struct {
		name string
		src  string
		data string
		want []string
	}{
		{"wide matches utf16le", `rule r { strings: $a = "AB" wide condition: $a }`, "xA\x00B\x00x", []string{"r"}},
		{"wide does not match ascii", `rule r { strings: $a = "AB" wide condition: $a }`, "xABx", nil},
		{"ascii wide matches ascii", `rule r { strings: $a = "AB" ascii wide condition: $a }`, "xABx", []string{"r"}},
		{"ascii wide matches wide", `rule r { strings: $a = "AB" ascii wide condition: $a }`, "A\x00B\x00", []string{"r"}},
		{"plain string does not match wide", `rule r { strings: $a = "AB" condition: $a }`, "A\x00B\x00", nil},
		{"wide nocase", `rule r { strings: $a = "ab" wide nocase condition: $a }`, "A\x00B\x00", []string{"r"}},
		{"wide fullword rejects trailing word char", `rule r { strings: $a = "AB" wide fullword condition: $a }`, "A\x00B\x00C\x00", nil},
		{"wide fullword rejects leading word char", `rule r { strings: $a = "AB" wide fullword condition: $a }`, "C\x00A\x00B\x00", nil},
		{"wide fullword accepts separators", `rule r { strings: $a = "AB" wide fullword condition: $a }`, " \x00A\x00B\x00 \x00", []string{"r"}},
		{"wide at offset", `rule r { strings: $a = "AB" wide condition: $a at 2 }`, "xxA\x00B\x00", []string{"r"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scanNames(t, compileSource(t, tt.src), []byte(tt.data))
			if !reflect.DeepEqual(got, tt.want) && !(len(got) == 0 && len(tt.want) == 0) {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestWideMatchDataIncludesZeroBytes(t *testing.T) {
	rules := compileSource(t, `rule r { strings: $a = "AB" wide condition: $a }`)
	var matches MatchRules
	if err := rules.ScanMem([]byte("A\x00B\x00"), 0, 0, &matches); err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 || string(matches[0].Strings[0].Data) != "A\x00B\x00" {
		t.Errorf("unexpected matches %+v", matches)
	}
}

func TestWideRegexIsSkipped(t *testing.T) {
	rules := compileSource(t, `rule r { strings: $a = /ab+c/ wide condition: $a }`)
	if rules.NumRules() != 0 {
		t.Errorf("expected wide regex rule to be skipped, got %d rules", rules.NumRules())
	}
}
