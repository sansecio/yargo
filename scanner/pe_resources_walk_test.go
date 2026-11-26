package scanner

import (
	"encoding/binary"
	"testing"
)

func resourcesOf(t *testing.T, b []byte) []peResource {
	t.Helper()
	info := parsePE(b, nil)
	if info == nil {
		t.Fatal("PE did not parse")
	}
	info.ensureResources()
	return info.resources
}

func TestPEResourceLeafAtTheTypeLevelHasNoIDOrLanguage(t *testing.T) {
	b := buildPEWithResources(t, [][2]string{{"A", "b"}})
	r := b[rsrcFileOffset:]
	binary.LittleEndian.PutUint32(r[24+4:], 0xB0)
	res := resourcesOf(t, b)
	if len(res) != 2 {
		t.Fatalf("got %d resources, want 2", len(res))
	}
	if got := res[1]; got.typ != (optInt{v: 16, ok: true}) || got.id.ok || got.language.ok {
		t.Errorf("leaf inherited the previous sibling: %+v", got)
	}
}

func TestPEResourceLeafAtTheNameLevelHasNoLanguage(t *testing.T) {
	b := buildPEWithResources(t, [][2]string{{"A", "b"}})
	r := b[rsrcFileOffset:]
	binary.LittleEndian.PutUint16(r[0x30+14:], 2)
	binary.LittleEndian.PutUint32(r[0x48:], 8)
	binary.LittleEndian.PutUint32(r[0x48+4:], 0xB0)
	res := resourcesOf(t, b)
	if len(res) != 3 {
		t.Fatalf("got %d resources, want 3", len(res))
	}
	if got := res[1]; got.id != (optInt{v: 8, ok: true}) || got.language.ok {
		t.Errorf("leaf inherited the language of the previous sibling: %+v", got)
	}
}

func TestPEResourceEntryWithZeroDataIsSkippedNotTerminating(t *testing.T) {
	b := buildPEWithResources(t, [][2]string{{"A", "b"}})
	r := b[rsrcFileOffset:]
	binary.LittleEndian.PutUint32(r[24+4:], 0)
	binary.LittleEndian.PutUint16(r[14:], 2)
	binary.LittleEndian.PutUint32(r[32:], 16)
	binary.LittleEndian.PutUint32(r[32+4:], 0x80000000|0x50)
	res := resourcesOf(t, b)
	if len(res) != 2 {
		t.Errorf("got %d resources, want 2 (the entry after the zero one was dropped)", len(res))
	}
}
