//go:build yara

package internal

import (
	"os"

	yara "github.com/hillu/go-yara/v4"
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
