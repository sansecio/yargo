package ast

import (
	"reflect"
	"slices"
	"testing"
)

// Fields that existed before the condition and module work keep their
// position, so unkeyed composite literals written against them still mean
// the same thing. New fields go after them.
func TestStructsKeepTheirOriginalFieldOrder(t *testing.T) {
	for _, tc := range []struct {
		v    any
		want []string
	}{
		{RuleSet{}, []string{"Rules", "Warnings"}},
		{Rule{}, []string{"Name", "Meta", "Strings", "Condition"}},
		{StringModifiers{}, []string{"Ascii", "Base64", "Fullword", "Nocase", "Private", "Unsupported"}},
	} {
		typ := reflect.TypeOf(tc.v)
		var got []string
		for i := range min(typ.NumField(), len(tc.want)) {
			got = append(got, typ.Field(i).Name)
		}
		if !slices.Equal(got, tc.want) {
			t.Errorf("%s fields start with %v, want %v", typ.Name(), got, tc.want)
		}
	}
}
