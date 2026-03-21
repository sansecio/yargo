//go:build js

package scanner

import (
	"fmt"
	"time"
)

// ScanFile is not supported in WebAssembly (js/wasm) environments because
// the browser sandbox does not provide filesystem access or memory mapping.
//
// Use [Rules.ScanMem] instead by reading file content into a byte slice
// and passing it directly. For example:
//
//	// In Go WASM, receive file content from JavaScript
//	data := []byte(js.Global().Call("getFileContent").String())
//
//	var matches MatchRules
//	err := rules.ScanMem(data, 0, 30*time.Second, &matches)
//	if err != nil {
//	    // handle error
//	}
//	for _, m := range matches {
//	    fmt.Println("Matched:", m.Rule)
//	}
//
// In a JavaScript context, you can read files using the File API or fetch:
//
//	// JavaScript side
//	const file = document.getElementById('fileInput').files[0];
//	const buffer = await file.arrayBuffer();
//	const uint8 = new Uint8Array(buffer);
//	// Pass uint8 to Go WASM via a registered function
func (r *Rules) ScanFile(filename string, flags ScanFlags, timeout time.Duration, cb ScanCallback) error {
	return fmt.Errorf("scanner: ScanFile is not supported in WASM — use ScanMem instead")
}
