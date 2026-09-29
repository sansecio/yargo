//go:build yara

package main

import (
	"time"

	"github.com/sansecio/yargo/cmd/internal"
)

func init() {
	compareGoYara = func(path string) (time.Duration, error) {
		start := time.Now()
		rules, err := internal.GoYaraRules(path)
		duration := time.Since(start)
		if err != nil {
			return 0, err
		}
		rules.Destroy()
		return duration, nil
	}
}
