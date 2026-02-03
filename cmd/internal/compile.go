package internal

import (
	"os"

	yara "github.com/hillu/go-yara/v4"
	"github.com/sansecio/yargo/parser"
	"github.com/sansecio/yargo/scanner"
)

func GoYaraRules(yaraFile string) (*yara.Rules, error) {
	compiler, err := yara.NewCompiler()
	if err != nil {
		return nil, err
	}

	f, err := os.Open(yaraFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	if err := compiler.AddFile(f, ""); err != nil {
		return nil, err
	}

	return compiler.GetRules()
}

func YargoRules(yaraFile string) (*scanner.Rules, error) {
	p := parser.New()
	ruleSet, err := p.ParseFile(yaraFile)
	if err != nil {
		return nil, err
	}

	return scanner.Compile(ruleSet)
}
