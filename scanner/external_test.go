package scanner

import (
	"reflect"
	"testing"
	"time"
)

func scanNamesWith(t *testing.T, rules *Rules, data []byte, ext Externals) []string {
	t.Helper()
	var matches MatchRules
	if err := rules.ScanMemWith(data, ext, 0, time.Second, &matches); err != nil {
		t.Fatalf("ScanMemWith() error = %v", err)
	}
	names := make([]string, 0, len(matches))
	for _, m := range matches {
		names = append(names, m.Rule)
	}
	return names
}

func TestExternalVariables(t *testing.T) {
	tests := []struct {
		name string
		cond string
		ext  Externals
		want []string
	}{
		{"filename equal", `filename == "a.exe"`, Externals{"filename": "a.exe"}, []string{"r"}},
		{"filename different", `filename == "a.exe"`, Externals{"filename": "b.exe"}, nil},
		{"filename not equal", `filename != "a.exe"`, Externals{"filename": "b.exe"}, []string{"r"}},
		{"unset external is undefined", `filename == "a.exe"`, nil, nil},
		{"unset external with not is undefined", `not filename == "a.exe"`, nil, nil},
		{"contains", `filepath contains "/etc/"`, Externals{"filepath": "/etc/passwd"}, []string{"r"}},
		{"contains is case sensitive", `filepath contains "/ETC/"`, Externals{"filepath": "/etc/passwd"}, nil},
		{"icontains", `filepath icontains "/ETC/"`, Externals{"filepath": "/etc/passwd"}, []string{"r"}},
		{"startswith", `filepath startswith "/etc"`, Externals{"filepath": "/etc/passwd"}, []string{"r"}},
		{"istartswith", `filepath istartswith "/ETC"`, Externals{"filepath": "/etc/passwd"}, []string{"r"}},
		{"endswith", `filename endswith ".exe"`, Externals{"filename": "a.exe"}, []string{"r"}},
		{"iendswith", `filename iendswith ".EXE"`, Externals{"filename": "a.exe"}, []string{"r"}},
		{"iequals", `filename iequals "A.EXE"`, Externals{"filename": "a.exe"}, []string{"r"}},
		{"matches", `filename matches /^a\.e.e$/`, Externals{"filename": "a.exe"}, []string{"r"}},
		{"matches case insensitive", `extension matches /^\.TXT$/i`, Externals{"extension": ".txt"}, []string{"r"}},
		{"not matches", `not filename matches /cpuz/i`, Externals{"filename": "CPUZ.exe"}, nil},
		{"not matches passes", `not filename matches /cpuz/i`, Externals{"filename": "a.exe"}, []string{"r"}},
		{"or of names", `filename == "x" or filename == "a.exe"`, Externals{"filename": "a.exe"}, []string{"r"}},
		{"true", `true`, nil, []string{"r"}},
		{"false", `false`, nil, nil},
		{"integer external", `level > 2`, Externals{"level": 3}, []string{"r"}},
		{"integer external int64", `level > 2`, Externals{"level": int64(1)}, nil},
		{"boolean external", `flag`, Externals{"flag": true}, []string{"r"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rules, err := compileWith(t, "rule r { condition: "+tt.cond+" }", CompileOptions{Externals: []string{"level", "flag"}})
			if err != nil {
				t.Fatal(err)
			}
			got := scanNamesWith(t, rules, []byte("data"), tt.ext)
			if !reflect.DeepEqual(got, tt.want) && !(len(got) == 0 && len(tt.want) == 0) {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestExternalWithStrings(t *testing.T) {
	rules := compileSource(t, `rule r { strings: $a = "abc" condition: $a and filename == "x.bin" }`)
	if got := scanNamesWith(t, rules, []byte("abc"), Externals{"filename": "x.bin"}); !reflect.DeepEqual(got, []string{"r"}) {
		t.Errorf("expected match, got %v", got)
	}
	if got := scanNamesWith(t, rules, []byte("abc"), Externals{"filename": "y.bin"}); len(got) != 0 {
		t.Errorf("expected no match, got %v", got)
	}
	if got := scanNames(t, rules, []byte("abc")); len(got) != 0 {
		t.Errorf("expected no match without externals, got %v", got)
	}
}

func TestRuleReferences(t *testing.T) {
	rules := compileSource(t, `
private rule is_magic { strings: $m = "MZ" condition: $m at 0 }
rule uses_magic { strings: $a = "abc" condition: is_magic and $a }
rule negated { strings: $a = "abc" condition: not is_magic and $a }`)
	if got := scanNames(t, rules, []byte("MZ abc")); !reflect.DeepEqual(got, []string{"uses_magic"}) {
		t.Errorf("expected only uses_magic, got %v", got)
	}
	if got := scanNames(t, rules, []byte("..abc")); !reflect.DeepEqual(got, []string{"negated"}) {
		t.Errorf("expected only negated, got %v", got)
	}
}

func TestUnknownIdentifierSkipsRule(t *testing.T) {
	rules := compileSource(t, `rule r { condition: entrypoint == 0 }
rule ok { condition: filesize > 0 }`)
	if rules.NumRules() != 1 {
		t.Fatalf("expected only the known rule to compile, got %d", rules.NumRules())
	}
	skipped := rules.Skipped()
	if len(skipped) != 1 || skipped[0].Rule != "r" {
		t.Errorf("expected rule r reported as skipped, got %+v", skipped)
	}
}
