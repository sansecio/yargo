package scanner

import (
	"encoding/binary"
	"testing"
	"time"
	"unicode/utf16"
)

func wide(s string, terminate bool) []byte {
	var out []byte
	for _, u := range utf16.Encode([]rune(s)) {
		out = binary.LittleEndian.AppendUint16(out, u)
	}
	if terminate {
		out = append(out, 0, 0)
	}
	return out
}

func pad4(b []byte) []byte {
	for len(b)%4 != 0 {
		b = append(b, 0)
	}
	return b
}

func versionNode(key string, valueLen int, typ uint16, value, children []byte) []byte {
	node := binary.LittleEndian.AppendUint16(nil, 0)
	node = binary.LittleEndian.AppendUint16(node, uint16(valueLen))
	node = binary.LittleEndian.AppendUint16(node, typ)
	node = append(node, wide(key, true)...)
	node = pad4(node)
	node = append(node, value...)
	node = pad4(node)
	node = append(node, children...)
	binary.LittleEndian.PutUint16(node, uint16(len(node)))
	return node
}

func versionString(key, value string) []byte {
	return versionNode(key, len(value)+1, 1, wide(value, true), nil)
}

func buildVersionBlob(pairs [][2]string) []byte {
	var strs []byte
	for _, kv := range pairs {
		strs = append(strs, pad4(versionString(kv[0], kv[1]))...)
	}
	table := pad4(versionNode("040904b0", 0, 1, nil, strs))
	info := pad4(versionNode("StringFileInfo", 0, 1, nil, table))
	return versionNode("VS_VERSION_INFO", 52, 0, make([]byte, 52), info)
}

const (
	rsrcFileOffset = 0xA00
	rsrcRVA        = 0x3000
	overlaySize    = 0x40
)

func buildPEWithResources(t *testing.T, pairs [][2]string) []byte {
	t.Helper()
	b := buildPE(t)
	le := binary.LittleEndian
	b = append(b, make([]byte, 0x400+overlaySize)...)
	le.PutUint16(b[0x46:], 3)
	le.PutUint32(b[0x58+128:], rsrcRVA)
	le.PutUint32(b[0x58+132:], 0x400)
	s := 0x58 + 240 + 80
	copy(b[s:], ".rsrc")
	le.PutUint32(b[s+8:], 0x400)
	le.PutUint32(b[s+12:], rsrcRVA)
	le.PutUint32(b[s+16:], 0x400)
	le.PutUint32(b[s+20:], rsrcFileOffset)
	r := b[rsrcFileOffset:]
	dir := func(at int, timestamp uint32, named, ids uint16) {
		le.PutUint32(r[at+4:], timestamp)
		le.PutUint16(r[at+8:], 1)
		le.PutUint16(r[at+10:], 2)
		le.PutUint16(r[at+12:], named)
		le.PutUint16(r[at+14:], ids)
	}
	entry := func(at int, name, data uint32) {
		le.PutUint32(r[at:], name)
		le.PutUint32(r[at+4:], data)
	}
	const sub = 0x80000000
	dir(0, 0x5555, 1, 1)
	entry(16, sub|0x100, sub|0x30)
	entry(24, 16, sub|0x50)
	le.PutUint16(r[0x100:], 4)
	copy(r[0x102:], wide("ABCD", false))
	dir(0x30, 0, 0, 1)
	entry(0x30+16, 7, sub|0x70)
	dir(0x50, 0, 0, 1)
	entry(0x50+16, 1, sub|0x90)
	dir(0x70, 0, 0, 1)
	entry(0x70+16, 0x409, 0xB0)
	dir(0x90, 0, 0, 1)
	entry(0x90+16, 0x409, 0xC0)
	le.PutUint32(r[0xB0:], rsrcRVA+0x200)
	le.PutUint32(r[0xB4:], 8)
	blob := buildVersionBlob(pairs)
	le.PutUint32(r[0xC0:], rsrcRVA+0x300)
	le.PutUint32(r[0xC4:], uint32(len(blob)))
	copy(r[0x300:], blob)
	return b
}

func TestPEResourcesVersionInfoAndOverlay(t *testing.T) {
	data := buildPEWithResources(t, [][2]string{{"CompanyName", "ACME"}, {"FileVersion", "1.2.3.4"}})
	tests := []struct {
		cond string
		want bool
	}{
		{"pe.number_of_resources == 2", true},
		{"pe.resource_timestamp == 0x5555", true},
		{"pe.resources[0].rva == 0x3200", true},
		{"pe.resources[0].offset == 0xC00", true},
		{"pe.resources[0].length == 8", true},
		{"pe.resources[0].id == 7", true},
		{"pe.resources[0].language == 0x409", true},
		{"pe.resources[0].type_string == \"A\\x00B\\x00C\\x00D\\x00\"", true},
		{"not pe.resources[0].type == 0", false},
		{"pe.resources[1].type == pe.RESOURCE_TYPE_VERSION", true},
		{"pe.resources[1].id == 1", true},
		{"not pe.resources[1].type_string == \"x\"", false},
		{"not pe.resources[2].length == 0", false},
		{"pe.number_of_version_infos == 2", true},
		{"pe.version_info[\"CompanyName\"] == \"ACME\"", true},
		{"pe.version_info[\"FileVersion\"] contains \"2.3\"", true},
		{"not pe.version_info[\"Missing\"] == \"x\"", false},
		{"pe.version_info_list[1].key == \"FileVersion\"", true},
		{"pe.version_info_list[1].value == \"1.2.3.4\"", true},
		{"pe.overlay.offset == 0xE00", true},
		{"pe.overlay.size == 0x40", true},
		{"pe.is_pe", true},
		{"for any i in (0..pe.number_of_resources-1) : (pe.resources[i].type == pe.RESOURCE_TYPE_VERSION)", true},
	}
	for _, tt := range tests {
		t.Run(tt.cond, func(t *testing.T) {
			rules := compileSource(t, "import \"pe\"\nrule r { condition: "+tt.cond+" }")
			if rules.NumRules() != 1 {
				t.Fatalf("rule skipped: %+v", rules.Skipped())
			}
			if got := len(scanNames(t, rules, data)) == 1; got != tt.want {
				t.Errorf("expected %v, got %v", tt.want, got)
			}
		})
	}
}

func TestPEOverlayIsZeroWithoutAppendedData(t *testing.T) {
	rules := compileSource(t, "import \"pe\" rule r { condition: pe.overlay.offset == 0 and pe.overlay.size == 0 }")
	if got := scanNames(t, rules, buildPE(t)); len(got) != 1 {
		t.Errorf("matches = %v", got)
	}
}

func TestPEResourceTimestampIsUndefinedWithoutResourceDirectory(t *testing.T) {
	for _, cond := range []string{"pe.resource_timestamp == 0", "not pe.resource_timestamp == 0"} {
		rules := compileSource(t, `import "pe" `+"rule r { condition: "+cond+" }")
		if got := scanNames(t, rules, buildPE(t)); len(got) != 0 {
			t.Errorf("%s matched a PE without resources", cond)
		}
	}
}

func TestPEMembersOnNonPEAreUndefined(t *testing.T) {
	for _, cond := range []string{
		"pe.overlay.size == 0", "not pe.overlay.size == 0",
		"pe.number_of_resources == 0", "not pe.number_of_resources == 0",
		`pe.version_info["a"] == ""`, `not pe.version_info["a"] == ""`,
		"pe.resources[0].length == 0", "not pe.resources[0].length == 0",
		"pe.number_of_signatures == 0", "not pe.number_of_signatures == 0",
	} {
		rules := compileSource(t, `import "pe" `+"rule r { condition: "+cond+" }")
		if got := scanNames(t, rules, []byte("not a pe")); len(got) != 0 {
			t.Errorf("%s matched a non-PE file", cond)
		}
	}
	rules := compileSource(t, "import \"pe\" rule r { condition: pe.is_pe }")
	if got := scanNames(t, rules, []byte("not a pe")); len(got) != 0 {
		t.Error("pe.is_pe is true for a non-PE file")
	}
	rules = compileSource(t, "import \"pe\" rule r { condition: not pe.is_pe }")
	if got := scanNames(t, rules, []byte("not a pe")); len(got) != 1 {
		t.Error("pe.is_pe is not zero for a non-PE file")
	}
}

func TestPEResourceWalkIsBoundedAgainstSharedDirectories(t *testing.T) {
	const n = 1000
	b := buildPEWithResources(t, [][2]string{{"a", "b"}})
	b = append(b, make([]byte, 0x10000)...)
	le := binary.LittleEndian
	s := 0x58 + 240 + 80
	le.PutUint32(b[s+8:], 0x10400)
	le.PutUint32(b[s+16:], 0x10400)
	le.PutUint32(b[0x58+132:], 0x10400)
	r := b[rsrcFileOffset:]
	clear(r[:0x8000])
	const sub = 0x80000000
	for _, d := range []struct {
		at   int
		next uint32
	}{{0, sub | 0x2000}, {0x2000, sub | 0x4000}, {0x4000, 0x6000}} {
		le.PutUint16(r[d.at+14:], n)
		for i := range n {
			le.PutUint32(r[d.at+16+8*i:], uint32(i+1))
			le.PutUint32(r[d.at+20+8*i:], d.next)
		}
	}
	le.PutUint32(r[0x6000:], rsrcRVA+0x200)
	le.PutUint32(r[0x6004:], 8)
	rules := compileSource(t, "import \"pe\" rule r { condition: pe.number_of_resources > 100000000 }")
	start := time.Now()
	scanNames(t, rules, b)
	if d := time.Since(start); d > time.Second {
		t.Errorf("scan took %v", d)
	}
	info := parsePE(b, nil)
	info.ensureResources()
	if len(info.resources) > maxResources {
		t.Errorf("collected %d resources", len(info.resources))
	}
}
