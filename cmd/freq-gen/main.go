package main

import (
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var extensions = map[string]bool{
	".php":   true,
	".php5":  true,
	".php8":  true,
	".phar":  true,
	".ini":   true,
	".phtml": true,
	".html":  true,
	".htm":   true,
	".js":    true,
	".jsx":   true,
	".sh":    true,
}

func main() {
	flag.Parse()
	dir := flag.Arg(0)
	if dir == "" {
		fmt.Fprintf(os.Stderr, "usage: freq-gen <directory>\n")
		os.Exit(1)
	}

	var counts [256]uint64
	var fileCount int
	var totalBytes uint64

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if !matchFile(path) {
			return nil
		}

		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer f.Close()

		buf := make([]byte, 32*1024)
		for {
			n, err := f.Read(buf)
			for _, b := range buf[:n] {
				counts[b]++
			}
			totalBytes += uint64(n)
			if err == io.EOF {
				break
			}
			if err != nil {
				return err
			}
		}
		fileCount++
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "error walking directory: %v\n", err)
		os.Exit(1)
	}

	if fileCount == 0 {
		fmt.Fprintf(os.Stderr, "no matching files found\n")
		os.Exit(1)
	}

	ranks := computeRanks(counts)
	printTable(ranks)

	fmt.Fprintf(os.Stderr, "%d files, %d bytes\n", fileCount, totalBytes)
}

func matchFile(path string) bool {
	if filepath.Base(path) == ".htaccess" {
		return true
	}
	return extensions[strings.ToLower(filepath.Ext(path))]
}

func computeRanks(counts [256]uint64) [256]byte {
	type entry struct {
		byteVal int
		count   uint64
	}

	entries := make([]entry, 256)
	for i := range entries {
		entries[i] = entry{byteVal: i, count: counts[i]}
	}

	sort.SliceStable(entries, func(i, j int) bool {
		return entries[i].count < entries[j].count
	})

	var ranks [256]byte
	rank := 0
	for i := range 256 {
		if i > 0 && entries[i].count != entries[i-1].count {
			rank = i
		}
		ranks[entries[i].byteVal] = byte(rank)
	}

	return ranks
}

func byteComment(b byte) string {
	switch {
	case b == '\t':
		return `'\t'`
	case b == '\n':
		return `'\n'`
	case b == '\r':
		return `'\r'`
	case b == '\'':
		return `'\''`
	case b == '\\':
		return `'\\'`
	case b >= 0x20 && b <= 0x7E:
		return fmt.Sprintf("'%c'", b)
	default:
		return fmt.Sprintf(`'\x%02x'`, b)
	}
}

func printTable(ranks [256]byte) {
	fmt.Println("package ahocorasick")
	fmt.Println()
	fmt.Println("var byteFrequencies = [256]byte{")
	for i := range 256 {
		fmt.Printf("\t%-4s // %s\n", fmt.Sprintf("%d,", ranks[i]), byteComment(byte(i)))
	}
	fmt.Println("}")
}
