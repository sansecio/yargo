package scanner

import (
	"bytes"
	"crypto/md5"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/sansecio/yargo/ast"
)

const (
	maxImportDescriptors = 4096
	maxImportThunks      = 1 << 14
	maxExportNames       = 1 << 14
	maxTotalImports      = 1 << 14
	maxNameBytes         = 1 << 20
	maxCString           = 512
)

type peImport struct {
	dll       string
	name      string
	ordinal   int64
	byOrdinal bool
}

type peExport struct {
	name    string
	ordinal int64
}

type peInfo struct {
	file       *pe.File
	buf        []byte
	is64       bool
	chars      int64
	subsystem  int64
	entry      int64
	imageBase  int64
	dllChars   int64
	imports    []peImport
	exports    []peExport
	numExports int64
	nameBytes  int
	walked     map[uint32]bool
	done       <-chan struct{}
}

func (p *peInfo) stopped() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *peInfo) full() bool {
	return len(p.imports) >= maxTotalImports || p.nameBytes >= maxNameBytes
}

type scanState struct {
	done     <-chan struct{}
	buf      []byte
	pe       *peInfo
	peParsed bool
}

func (s *scanState) peInfo() *peInfo {
	if !s.peParsed {
		s.peParsed = true
		s.pe = parsePE(s.buf, s.done)
	}
	return s.pe
}

func parsePE(buf []byte, done <-chan struct{}) *peInfo {
	if len(buf) < 0x40 || buf[0] != 'M' || buf[1] != 'Z' {
		return nil
	}
	f, err := pe.NewFile(bytes.NewReader(buf))
	if err != nil {
		return nil
	}
	info := &peInfo{file: f, buf: buf, chars: int64(f.Characteristics), walked: map[uint32]bool{}, done: done}
	var dirs []pe.DataDirectory
	switch oh := f.OptionalHeader.(type) {
	case *pe.OptionalHeader64:
		info.is64 = true
		info.subsystem, info.entry = int64(oh.Subsystem), int64(oh.AddressOfEntryPoint)
		info.imageBase, info.dllChars = int64(oh.ImageBase), int64(oh.DllCharacteristics)
		dirs = oh.DataDirectory[:]
	case *pe.OptionalHeader32:
		info.subsystem, info.entry = int64(oh.Subsystem), int64(oh.AddressOfEntryPoint)
		info.imageBase, info.dllChars = int64(oh.ImageBase), int64(oh.DllCharacteristics)
		dirs = oh.DataDirectory[:]
	default:
		return nil
	}
	rva := info.entry
	info.entry = -1
	if off, ok := info.rvaToOffset(uint32(rva)); ok {
		info.entry = int64(off)
	}
	if len(dirs) > 1 {
		info.parseExports(dirs[0])
		info.parseImports(dirs[1])
	}
	return info
}

func (p *peInfo) rvaToOffset(rva uint32) (int, bool) {
	for _, s := range p.file.Sections {
		span := max(s.VirtualSize, s.Size)
		if rva >= s.VirtualAddress && rva-s.VirtualAddress < span {
			off := uint64(s.Offset) + uint64(rva-s.VirtualAddress)
			return int(off), off < uint64(len(p.buf))
		}
	}
	return 0, false
}

func (p *peInfo) u16(off int) (uint16, bool) {
	if off < 0 || off > len(p.buf)-2 {
		return 0, false
	}
	return binary.LittleEndian.Uint16(p.buf[off:]), true
}

func (p *peInfo) u32(off int) (uint32, bool) {
	if off < 0 || off > len(p.buf)-4 {
		return 0, false
	}
	return binary.LittleEndian.Uint32(p.buf[off:]), true
}

func (p *peInfo) u64(off int) (uint64, bool) {
	if off < 0 || off > len(p.buf)-8 {
		return 0, false
	}
	return binary.LittleEndian.Uint64(p.buf[off:]), true
}

func (p *peInfo) cstring(rva uint32) (string, bool) {
	off, ok := p.rvaToOffset(rva)
	if !ok {
		return "", false
	}
	end := min(len(p.buf), off+maxCString)
	n := bytes.IndexByte(p.buf[off:end], 0)
	if n < 0 {
		return "", false
	}
	return string(p.buf[off : off+n]), true
}

func (p *peInfo) parseExports(dir pe.DataDirectory) {
	if dir.VirtualAddress == 0 {
		return
	}
	base, ok := p.rvaToOffset(dir.VirtualAddress)
	if !ok {
		return
	}
	first, ok1 := p.u32(base + 16)
	numFuncs, ok2 := p.u32(base + 20)
	numNames, ok3 := p.u32(base + 24)
	namesRVA, ok4 := p.u32(base + 32)
	ordsRVA, ok5 := p.u32(base + 36)
	if !ok1 || !ok2 || !ok3 || !ok4 || !ok5 {
		return
	}
	p.numExports = int64(numFuncs)
	namesOff, nok := p.rvaToOffset(namesRVA)
	ordsOff, ook := p.rvaToOffset(ordsRVA)
	if !nok || !ook {
		return
	}
	for i := 0; i < int(min(numNames, maxExportNames)); i++ {
		if p.full() || (i%256 == 0 && p.stopped()) {
			return
		}
		nameRVA, ok := p.u32(namesOff + 4*i)
		if !ok {
			return
		}
		idx, ok := p.u16(ordsOff + 2*i)
		if !ok {
			return
		}
		name, ok := p.cstring(nameRVA)
		if !ok {
			continue
		}
		p.nameBytes += len(name)
		p.exports = append(p.exports, peExport{name: name, ordinal: int64(first) + int64(idx)})
	}
}

func (p *peInfo) parseImports(dir pe.DataDirectory) {
	if dir.VirtualAddress == 0 {
		return
	}
	base, ok := p.rvaToOffset(dir.VirtualAddress)
	if !ok {
		return
	}
	for i := 0; i < maxImportDescriptors; i++ {
		if p.full() || p.stopped() {
			return
		}
		d := base + 20*i
		oft, ok1 := p.u32(d)
		nameRVA, ok2 := p.u32(d + 12)
		ft, ok3 := p.u32(d + 16)
		if !ok1 || !ok2 || !ok3 || (oft == 0 && nameRVA == 0 && ft == 0) {
			return
		}
		dll, ok := p.cstring(nameRVA)
		if !ok {
			continue
		}
		thunks := oft
		if thunks == 0 {
			thunks = ft
		}
		if p.walked[thunks] {
			continue
		}
		p.walked[thunks] = true
		p.parseThunks(dll, thunks)
	}
}

func (p *peInfo) parseThunks(dll string, rva uint32) {
	off, ok := p.rvaToOffset(rva)
	if !ok {
		return
	}
	size := 4
	if p.is64 {
		size = 8
	}
	for i := 0; i < maxImportThunks; i++ {
		if p.full() || (i%256 == 0 && p.stopped()) {
			return
		}
		var v uint64
		if p.is64 {
			v, ok = p.u64(off + size*i)
		} else {
			var v32 uint32
			v32, ok = p.u32(off + size*i)
			v = uint64(v32)
		}
		if !ok || v == 0 {
			return
		}
		ordFlag := uint64(1) << 31
		if p.is64 {
			ordFlag = 1 << 63
		}
		if v&ordFlag != 0 {
			p.imports = append(p.imports, peImport{dll: dll, ordinal: int64(v & 0xffff), byOrdinal: true})
			continue
		}
		name, ok := p.cstring(uint32(v) + 2)
		if ok {
			p.nameBytes += len(name)
			p.imports = append(p.imports, peImport{dll: dll, name: name})
		}
	}
}

func (p *peInfo) imphash() string {
	var sb strings.Builder
	for i, imp := range p.imports {
		if i > 0 {
			sb.WriteByte(',')
		}
		dll := strings.ToLower(imp.dll)
		for _, ext := range []string{".dll", ".ocx", ".sys"} {
			dll = strings.TrimSuffix(dll, ext)
		}
		sb.WriteString(dll)
		sb.WriteByte('.')
		if imp.byOrdinal {
			sb.WriteString("ord")
			sb.WriteString(itoa(imp.ordinal))
		} else {
			sb.WriteString(strings.ToLower(imp.name))
		}
	}
	sum := md5.Sum([]byte(sb.String()))
	return hex.EncodeToString(sum[:])
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var b [20]byte
	i := len(b)
	for ; n > 0; n /= 10 {
		i--
		b[i] = byte('0' + n%10)
	}
	return string(b[i:])
}

var peConstants = map[string]int64{
	"pe.RELOCS_STRIPPED": 0x1, "pe.EXECUTABLE_IMAGE": 0x2, "pe.LINE_NUMS_STRIPPED": 0x4,
	"pe.LOCAL_SYMS_STRIPPED": 0x8, "pe.LARGE_ADDRESS_AWARE": 0x20, "pe.32BIT_MACHINE": 0x100,
	"pe.DEBUG_STRIPPED": 0x200, "pe.SYSTEM": 0x1000, "pe.DLL": 0x2000,
	"pe.MACHINE_UNKNOWN": 0, "pe.MACHINE_I386": 0x14c, "pe.MACHINE_AMD64": 0x8664,
	"pe.MACHINE_ARM": 0x1c0, "pe.MACHINE_ARM64": 0xaa64,
	"pe.SUBSYSTEM_NATIVE": 1, "pe.SUBSYSTEM_WINDOWS_GUI": 2, "pe.SUBSYSTEM_WINDOWS_CUI": 3,
	"pe.SUBSYSTEM_EFI_APPLICATION": 10,
}

var peScalars = map[string]bool{
	"pe.machine": true, "pe.timestamp": true, "pe.characteristics": true, "pe.subsystem": true,
	"pe.entry_point": true, "pe.image_base": true, "pe.dll_characteristics": true,
	"pe.number_of_sections": true, "pe.number_of_exports": true,
}

var peFunctions = map[string]int{
	"pe.is_dll": 0, "pe.is_32bit": 0, "pe.is_64bit": 0, "pe.imphash": 0,
	"pe.exports": 1, "pe.section_index": 1,
}

var peSectionFields = map[string]bool{
	"name": true, "raw_data_size": true, "raw_data_offset": true, "virtual_size": true,
	"virtual_address": true, "characteristics": true,
}

func supportedPEFunction(name string, args int) bool {
	if want, ok := peFunctions[name]; ok {
		return want == args
	}
	return name == "pe.imports" && (args == 1 || args == 2)
}

func supportedPEMember(expr ast.Expr) bool {
	switch e := expr.(type) {
	case ast.Ident:
		_, isConst := peConstants[e.Name]
		return isConst || peScalars[e.Name]
	case ast.Field:
		idx, ok := e.Base.(ast.Index)
		if !ok {
			return false
		}
		id, ok := idx.Base.(ast.Ident)
		return ok && id.Name == "pe.sections" && peSectionFields[e.Name]
	}
	return false
}

func (p *peInfo) scalar(name string) any {
	switch name {
	case "pe.machine":
		return int64(p.file.Machine)
	case "pe.timestamp":
		return int64(p.file.TimeDateStamp)
	case "pe.characteristics":
		return p.chars
	case "pe.subsystem":
		return p.subsystem
	case "pe.entry_point":
		if p.entry < 0 {
			return nil
		}
		return p.entry
	case "pe.image_base":
		return p.imageBase
	case "pe.dll_characteristics":
		return p.dllChars
	case "pe.number_of_sections":
		return int64(len(p.file.Sections))
	case "pe.number_of_exports":
		return p.numExports
	}
	return nil
}

func (p *peInfo) sectionField(i int64, field string) any {
	if i < 0 || i >= int64(len(p.file.Sections)) {
		return nil
	}
	s := p.file.Sections[i]
	switch field {
	case "name":
		return s.Name
	case "raw_data_size":
		return int64(s.Size)
	case "raw_data_offset":
		return int64(s.Offset)
	case "virtual_size":
		return int64(s.VirtualSize)
	case "virtual_address":
		return int64(s.VirtualAddress)
	case "characteristics":
		return int64(s.Characteristics)
	}
	return nil
}

func (p *peInfo) call(name string, args []any) any {
	switch name {
	case "pe.is_dll":
		return p.chars&0x2000 != 0
	case "pe.is_32bit":
		return !p.is64
	case "pe.is_64bit":
		return p.is64
	case "pe.imphash":
		return p.imphash()
	case "pe.section_index":
		want, ok := args[0].(string)
		if !ok {
			return nil
		}
		for i, s := range p.file.Sections {
			if s.Name == want {
				return int64(i)
			}
		}
		return nil
	case "pe.exports":
		for _, e := range p.exports {
			if n, ok := args[0].(string); ok && e.name == n {
				return true
			}
			if o, ok := args[0].(int64); ok && e.ordinal == o {
				return true
			}
		}
		if o, ok := args[0].(int64); ok && p.numExports > 0 && len(p.exports) == 0 {
			return o > 0 && o <= p.numExports
		}
		return false
	case "pe.imports":
		return p.countImports(args)
	}
	return nil
}

func (p *peInfo) countImports(args []any) any {
	dll, ok := args[0].(string)
	if !ok {
		return nil
	}
	var n int64
	for _, imp := range p.imports {
		if !strings.EqualFold(imp.dll, dll) {
			continue
		}
		if len(args) == 1 {
			n++
			continue
		}
		switch fn := args[1].(type) {
		case string:
			if !imp.byOrdinal && imp.name == fn {
				n++
			}
		case int64:
			if imp.byOrdinal && imp.ordinal == fn {
				n++
			}
		}
	}
	return n
}
