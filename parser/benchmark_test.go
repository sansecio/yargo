package parser

import "testing"

var benchInput = `
rule detect_malware {
	meta:
		author = "test"
		severity = 8
	strings:
		$mz = "MZ"
		$pe = "PE\x00\x00"
		$suspicious = "CreateRemoteThread"
	condition:
		($mz at 0) and $pe and $suspicious
}

rule webshell_php {
	strings:
		$eval = /eval\s*\(/
		$b64 = "base64_decode"
		$sys = /(system|passthru|shell_exec)\s*\(/
	condition:
		any of them
}

rule packed_binary {
	strings:
		$upx = { 55 50 58 30 }
		$sec = ".packed"
		$ep = { 60 BE ?? ?? ?? ?? 8D BE }
	condition:
		$upx or ($sec and $ep)
}

rule network_ioc {
	meta:
		description = "Detect network indicators"
	strings:
		$ua = "Mozilla/4.0" fullword
		$dns = "malicious.example.com"
		$hex = { 4D 5A [4-16] 50 45 }
	condition:
		any of them
}
`

func BenchmarkParse(b *testing.B) {
	p := New()

	for b.Loop() {
		_, err := p.Parse(benchInput)
		if err != nil {
			b.Fatalf("Parse() error = %v", err)
		}
	}
}
