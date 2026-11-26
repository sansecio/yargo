package scanner

import "strings"

const (
	maxResources        = 65536
	maxResourceEntries  = 1 << 18
	maxVersionInfos     = 1 << 12
	maxResourceNameLen  = 1000
	maxVersionKeyChars  = 63
	maxVersionValChars  = 255
	resourceTypeVersion = 16
)

// opt is a module value that may be undefined.
type opt[T any] struct {
	v  T
	ok bool
}

func (o opt[T]) value() any {
	if !o.ok {
		return nil
	}
	return o.v
}

type peResource struct {
	rva, offset, length int64
	hasOffset           bool
	typ, id, language   opt[int64]
	typeStr, nameStr    opt[string]
	languageStr         opt[string]
}

type versionEntry struct {
	key, value string
}

type resourceWalk struct {
	p        *peInfo
	base     int
	visited  int
	typ      int64
	id       int64
	language int64
}

func align4(n int) int {
	return (n + 3) &^ 3
}

func (p *peInfo) fits(off, size int) bool {
	return off >= 0 && size >= 0 && size <= len(p.buf) && off <= len(p.buf)-size
}

func (p *peInfo) ensureResources() {
	if p.resourcesParsed {
		return
	}
	p.resourcesParsed = true
	p.versionInfo = map[string]string{}
	if len(p.dirs) <= 2 || p.dirs[2].VirtualAddress == 0 {
		return
	}
	base, ok := p.rvaToOffset(p.dirs[2].VirtualAddress)
	if !ok || !p.fits(base, 16) {
		return
	}
	ts, _ := p.u32(base + 4)
	p.resourceTimestamp = int64(ts)
	p.hasResourceDir = true
	w := &resourceWalk{p: p, base: base, typ: -1, id: -1, language: -1}
	w.dir(base, 0, opt[string]{}, opt[string]{}, opt[string]{})
}

func (w *resourceWalk) name(entryName uint32) opt[string] {
	if entryName&0x80000000 == 0 {
		return opt[string]{}
	}
	off := w.base + int(entryName&0x7FFFFFFF)
	length, ok := w.p.u16(off)
	if !ok || length > maxResourceNameLen || !w.p.fits(off, 2+int(length)*2) {
		return opt[string]{}
	}
	return opt[string]{v: string(w.p.buf[off+2 : off+2+int(length)*2]), ok: true}
}

func (w *resourceWalk) dir(off, level int, typeStr, nameStr, langStr opt[string]) {
	chars, _ := w.p.u32(off)
	named, _ := w.p.u16(off + 12)
	ids, _ := w.p.u16(off + 14)
	if chars != 0 || named > 32768 || ids > 32768 {
		return
	}
	total := int(named) + int(ids)
	entries := off + 16
	if !w.p.fits(entries, total*8) {
		return
	}
	for i := range total {
		w.visited++
		if w.visited > maxResourceEntries || (w.visited%256 == 0 && w.p.stopped()) {
			return
		}
		e := entries + 8*i
		entryName, _ := w.p.u32(e)
		data, _ := w.p.u32(e + 4)
		if data == 0 {
			continue
		}
		switch level {
		case 0:
			w.id, w.language = -1, -1
			w.typ = int64(int32(entryName))
			typeStr = w.name(entryName)
		case 1:
			w.language = -1
			w.id = int64(int32(entryName))
			nameStr = w.name(entryName)
		case 2:
			w.language = int64(int32(entryName))
			langStr = w.name(entryName)
		}
		target := w.base + int(data&0x7FFFFFFF)
		if data&0x80000000 != 0 && level < 2 {
			if w.p.fits(target, 16) {
				w.dir(target, level+1, typeStr, nameStr, langStr)
			}
			continue
		}
		if !w.p.fits(target, 16) {
			continue
		}
		rva, _ := w.p.u32(target)
		size, _ := w.p.u32(target + 4)
		if size == 0 || size > 0x3FFFFFFF {
			continue
		}
		w.collect(rva, size, typeStr, nameStr, langStr)
	}
}

func optValue(s opt[string], n int64) (opt[int64], opt[string]) {
	if s.ok {
		return opt[int64]{}, s
	}
	if n != -1 {
		return opt[int64]{v: n, ok: true}, opt[string]{}
	}
	return opt[int64]{}, opt[string]{}
}

func (w *resourceWalk) collect(rva, size uint32, typeStr, nameStr, langStr opt[string]) {
	p := w.p
	if len(p.resources) >= maxResources {
		return
	}
	r := peResource{rva: int64(rva), length: int64(size)}
	if off, ok := p.rvaToOffset(rva); ok {
		r.offset, r.hasOffset = int64(off), true
	}
	r.typ, r.typeStr = optValue(typeStr, w.typ)
	r.id, r.nameStr = optValue(nameStr, w.id)
	r.language, r.languageStr = optValue(langStr, w.language)
	if w.typ == resourceTypeVersion && !p.stopped() {
		p.parseVersionInfo(rva)
	}
	p.resources = append(p.resources, r)
}

func (p *peInfo) wideFits(off, end int) bool {
	for end = min(end, len(p.buf)); off >= 0 && off <= end-2; off += 2 {
		if p.buf[off] == 0 && p.buf[off+1] == 0 {
			return true
		}
	}
	return false
}

func (p *peInfo) wideLen(off, end int) int {
	n := 0
	end = min(end, len(p.buf))
	for off+2*n+1 < end && (p.buf[off+2*n] != 0 || p.buf[off+2*n+1] != 0) {
		n++
	}
	return n
}

func (p *peInfo) wideEquals(off int, s string) bool {
	if !p.fits(off, 2*(len(s)+1)) {
		return false
	}
	for i := range len(s) {
		if p.buf[off+2*i] != s[i] || p.buf[off+2*i+1] != 0 {
			return false
		}
	}
	return p.buf[off+2*len(s)] == 0 && p.buf[off+2*len(s)+1] == 0
}

func (p *peInfo) narrow(off, limit int) string {
	var sb strings.Builder
	for i := 0; i < limit && off+2*i < len(p.buf) && p.buf[off+2*i] != 0; i++ {
		sb.WriteByte(p.buf[off+2*i])
	}
	return sb.String()
}

func (p *peInfo) node(off int) (length int, ok bool) {
	if !p.fits(off, 6) {
		return 0, false
	}
	l, _ := p.u16(off)
	return int(l), true
}

func (p *peInfo) parseVersionInfo(rva uint32) {
	if p.versionParsed[rva] {
		return
	}
	if p.versionParsed == nil {
		p.versionParsed = map[uint32]bool{}
	}
	p.versionParsed[rva] = true
	off, ok := p.rvaToOffset(rva)
	if !ok || !p.fits(off, 6) || !p.fits(off+6, 32) || !p.wideEquals(off+6, "VS_VERSION_INFO") {
		return
	}
	off += align4(6 + 86)
	for p.fits(off+6, 24) && p.wideEquals(off+6, "VarFileInfo") && !p.stopped() {
		length, _ := p.u16(off)
		if length == 0 {
			break
		}
		off += align4(int(length))
	}
	for p.fits(off+6, 30) && p.wideEquals(off+6, "StringFileInfo") && !p.stopped() {
		length, _ := p.u16(off)
		if length == 0 {
			break
		}
		table := off + align4(6+30)
		off += align4(int(length))
		p.parseStringTables(table, off)
	}
}

func (p *peInfo) parseStringTables(table, end int) {
	for {
		tableLen, ok := p.node(table)
		if !ok || !p.wideFits(table+6, table+tableLen) || tableLen == 0 || table >= end || p.stopped() {
			return
		}
		str := table + align4(6+2*(p.wideLen(table+6, table+tableLen)+1))
		table += align4(tableLen)
		if !p.parseStrings(str, table) {
			return
		}
	}
}

func (p *peInfo) parseStrings(str, end int) bool {
	for {
		strLen, ok := p.node(str)
		if !ok || !p.wideFits(str+6, str+strLen) || strLen == 0 || str >= end {
			return true
		}
		if len(p.versionList) >= maxVersionInfos || p.stopped() {
			return false
		}
		valueOff := str + align4(6+2*(p.wideLen(str+6, str+strLen)+1))
		if p.wideFits(valueOff, str+strLen) {
			key := p.narrow(str+6, maxVersionKeyChars)
			value := p.narrow(valueOff, maxVersionValChars)
			if valueLen, _ := p.u16(str + 2); valueLen == 0 {
				value = ""
			}
			p.versionInfo[key] = value
			p.versionList = append(p.versionList, versionEntry{key: key, value: value})
		}
		str += align4(strLen)
	}
}

func (p *peInfo) resourceField(i int64, field string) any {
	p.ensureResources()
	if i < 0 || i >= int64(len(p.resources)) {
		return nil
	}
	r := p.resources[i]
	switch field {
	case "rva":
		return r.rva
	case "offset":
		if !r.hasOffset {
			return nil
		}
		return r.offset
	case "length":
		return r.length
	case "type":
		return r.typ.value()
	case "id":
		return r.id.value()
	case "language":
		return r.language.value()
	case "type_string":
		return r.typeStr.value()
	case "name_string":
		return r.nameStr.value()
	case "language_string":
		return r.languageStr.value()
	}
	return nil
}

func (p *peInfo) versionInfoField(key string) any {
	p.ensureResources()
	v, ok := p.versionInfo[key]
	if !ok {
		return nil
	}
	return v
}

func (p *peInfo) versionInfoListField(i int64, field string) any {
	p.ensureResources()
	if i < 0 || i >= int64(len(p.versionList)) {
		return nil
	}
	if field == "key" {
		return p.versionList[i].key
	}
	return p.versionList[i].value
}
