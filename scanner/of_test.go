package scanner

import (
	"reflect"
	"testing"
)

func TestStringSetQuantifiers(t *testing.T) {
	const strs = `strings: $a1 = "aaa" $a2 = "bbb" $b = "ccc" `
	tests := []struct {
		name string
		cond string
		data string
		want []string
	}{
		{"2 of them with two", "2 of them", "aaa bbb", []string{"r"}},
		{"2 of them with one", "2 of them", "aaa", nil},
		{"1 of wildcard", "1 of ($a*)", "bbb", []string{"r"}},
		{"2 of wildcard with one", "2 of ($a*)", "bbb", nil},
		{"2 of mixed list", "2 of ($a*, $b)", "aaa ccc", []string{"r"}},
		{"overlapping patterns count once", "2 of ($a1, $a*)", "aaa", nil},
		{"none of them with hit", "none of them", "ccc", nil},
		{"none of them without hit", "none of them", "zzz", []string{"r"}},
		{"none of wildcard", "none of ($a*)", "ccc", []string{"r"}},
		{"any of list", "any of ($a1, $b)", "ccc", []string{"r"}},
		{"any of list without hit", "any of ($a1, $b)", "bbb", nil},
		{"all of list", "all of ($a1, $b)", "aaa ccc", []string{"r"}},
		{"all of list missing one", "all of ($a1, $b)", "aaa", nil},
		{"N of combined with and", "2 of them and filesize < 1KB", "aaa bbb", []string{"r"}},
		{"3 of them", "3 of them", "aaa bbb ccc", []string{"r"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules := compileSource(t, "rule r { "+strs+"condition: "+tt.cond+" }")
			got := scanNames(t, rules, []byte(tt.data))
			if !reflect.DeepEqual(got, tt.want) && !(len(got) == 0 && len(tt.want) == 0) {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestNoneOfRuleMatchesWithoutHits(t *testing.T) {
	rules := compileSource(t, `rule r { strings: $a = "aaa" condition: none of them }`)
	if got := scanNames(t, rules, []byte("zzz")); !reflect.DeepEqual(got, []string{"r"}) {
		t.Errorf("expected rule to match without any string hit, got %v", got)
	}
}
