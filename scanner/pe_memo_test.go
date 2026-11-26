package scanner

import (
	"encoding/binary"
	"strconv"
	"testing"
)

const memoLeaves = 2000

func versionPairs() [][2]string {
	var pairs [][2]string
	for i := range 500 {
		pairs = append(pairs, [2]string{"Key" + strconv.Itoa(i), "value of entry number " + strconv.Itoa(i)})
	}
	return pairs
}

func buildHeavyVersionBlob() []byte {
	blob := versionNode("VS_VERSION_INFO", 52, 0, make([]byte, 52), nil)
	for range 16 {
		node := binary.LittleEndian.AppendUint16(nil, 0xFFFC)
		node = binary.LittleEndian.AppendUint16(node, 0)
		node = binary.LittleEndian.AppendUint16(node, 1)
		node = append(node, wide("StringFileInfo", true)...)
		for len(node) < 0xFFFC {
			node = append(node, 0xFF)
		}
		blob = append(blob, node...)
	}
	return blob
}

func buildPEWithRepeatedVersionResource(t *testing.T, blob []byte) []byte {
	dirAt, entryAt, blobAt := 0x1000, 0x1000+16+8*memoLeaves+64, 0x1000+16+8*memoLeaves+128
	size := blobAt + len(blob)
	b := buildPEWithResources(t, [][2]string{{"A", "b"}})
	le := binary.LittleEndian
	b = append(b, make([]byte, size)...)
	s := 0x58 + 240 + 80
	le.PutUint32(b[s+8:], uint32(0x400+size))
	le.PutUint32(b[s+16:], uint32(0x400+size))
	r := b[rsrcFileOffset:]
	le.PutUint32(r[0x50+16+4:], 0x80000000|uint32(dirAt))
	le.PutUint16(r[dirAt+14:], memoLeaves)
	for i := range memoLeaves {
		le.PutUint32(r[dirAt+16+8*i:], uint32(i+1))
		le.PutUint32(r[dirAt+16+8*i+4:], uint32(entryAt))
	}
	le.PutUint32(r[entryAt:], rsrcRVA+uint32(blobAt))
	le.PutUint32(r[entryAt+4:], uint32(len(blob)))
	copy(r[blobAt:], blob)
	return b
}

func TestPEVersionInfoIsParsedOncePerDistinctRVA(t *testing.T) {
	b := buildPEWithRepeatedVersionResource(t, buildVersionBlob(versionPairs()))
	info := parsePE(b, nil)
	if info == nil {
		t.Fatal("PE did not parse")
	}
	info.ensureResources()
	if got := len(info.resources); got < memoLeaves {
		t.Fatalf("fixture has %d resources, want at least %d", got, memoLeaves)
	}
	if got := len(info.versionList); got != 500 {
		t.Errorf("version list has %d entries, want 500 (one parse)", got)
	}
}

func BenchmarkPEResourcesRepeatedVersionRVA(b *testing.B) {
	data := buildPEWithRepeatedVersionResource(&testing.T{}, buildHeavyVersionBlob())
	b.ResetTimer()
	for range b.N {
		info := parsePE(data, nil)
		info.ensureResources()
	}
}

func BenchmarkPEImphashRepeated(b *testing.B) {
	info := parsePE(buildPE(&testing.T{}), nil)
	for range 4000 {
		info.imports = append(info.imports, peImport{dll: "kernel32.dll", name: "function"})
	}
	b.ResetTimer()
	for range b.N {
		info.call("pe.imphash", nil)
	}
}
