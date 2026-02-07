package internal

import (
	"github.com/sansecio/yargo/parser"
	"github.com/sansecio/yargo/scanner"
)

func YargoRules(yaraFile string) (*scanner.Rules, error) {
	p := parser.New()
	ruleSet, err := p.ParseFile(yaraFile)
	if err != nil {
		return nil, err
	}

	return scanner.Compile(ruleSet)
}
