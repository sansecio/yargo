package main

import (
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/coregx/coregex"
)

func main() {
	pattern := `=(\$\w{1,10}\(['"][^\)]{1,200}\)\.chr\(\d{1,64}\)\.){2}`

	data, _ := os.ReadFile("/tmp/Product.php")
	fmt.Printf("Pattern: %s\n", pattern)
	fmt.Printf("Data size: %d bytes\n\n", len(data))

	stdlibRe := regexp.MustCompile(pattern)
	coregRe := coregex.MustCompile(pattern)

	start := time.Now()
	stdlibRe.Match(data)
	fmt.Printf("stdlib:  %v\n", time.Since(start))

	start = time.Now()
	coregRe.Match(data)
	fmt.Printf("coregex: %v\n", time.Since(start))
}
