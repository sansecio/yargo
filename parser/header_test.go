package parser

import (
	"errors"
	"reflect"
	"testing"
)

func TestParseImports(t *testing.T) {
	rs := mustParse(t, `import "pe"
import "math"
rule t { condition: 1 == 1 }`)
	want := []string{"pe", "math"}
	if !reflect.DeepEqual(rs.Imports, want) {
		t.Errorf("expected imports %v, got %v", want, rs.Imports)
	}
}

func TestParseRuleTags(t *testing.T) {
	rs := mustParse(t, `rule t : first second { condition: 1 == 1 }`)
	want := []string{"first", "second"}
	if !reflect.DeepEqual(rs.Rules[0].Tags, want) {
		t.Errorf("expected tags %v, got %v", want, rs.Rules[0].Tags)
	}
}

func TestParseRuleModifiers(t *testing.T) {
	rs := mustParse(t, `private rule a { condition: 1 == 1 }
global rule b : tag { condition: 1 == 1 }
rule c { condition: 1 == 1 }`)
	if !rs.Rules[0].Private || rs.Rules[0].Global {
		t.Errorf("rule a: expected private only, got %+v", rs.Rules[0])
	}
	if rs.Rules[1].Private || !rs.Rules[1].Global || len(rs.Rules[1].Tags) != 1 {
		t.Errorf("rule b: expected global with one tag, got %+v", rs.Rules[1])
	}
	if rs.Rules[2].Private || rs.Rules[2].Global {
		t.Errorf("rule c: expected plain rule, got %+v", rs.Rules[2])
	}
}

func TestParseErrorReportsLine(t *testing.T) {
	_, err := New().Parse("rule a { condition: 1 == 1 }\n\nrule b { condition: ) }")
	if err == nil {
		t.Fatal("expected parse error")
	}
	if err.Error() != "parse error: syntax error" {
		t.Errorf("error text = %q, want main's %q", err.Error(), "parse error: syntax error")
	}
	var perr *Error
	if !errors.As(err, &perr) || perr.Line != 3 {
		t.Errorf("expected a *parser.Error on line 3, got %#v", err)
	}
}
