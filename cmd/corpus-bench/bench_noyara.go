//go:build !yara

package main

import (
	"fmt"
	"time"
)

func benchGoYara(_ string, _ []corpusFile) (time.Duration, int, bool) {
	fmt.Println("go-yara disabled (build with -tags yara to enable); skipping")
	return 0, 0, false
}
