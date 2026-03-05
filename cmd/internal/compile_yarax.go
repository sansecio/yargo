//go:build yara

package internal

import (
	"fmt"
	"os"

	yarax "github.com/VirusTotal/yara-x/go"
)

func YaraXRules(yaraFile string) (*yarax.Rules, error) {
	src, err := os.ReadFile(yaraFile)
	if err != nil {
		return nil, err
	}

	c, err := yarax.NewCompiler(yarax.RelaxedReSyntax(true))
	if err != nil {
		return nil, err
	}

	// AddSource may return errors for individual rules, but compilation
	// continues — failing rules are simply excluded from the result.
	if err := c.AddSource(string(src)); err != nil {
		fmt.Fprintf(os.Stderr, "yara-x: some rules failed to compile: %v\n", err)
	}

	return c.Build(), nil
}
