package scanner

import (
	"bytes"
	"crypto/md5"
	"debug/pe"
	"encoding/binary"
	"encoding/hex"
	"strconv"
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
	maxPESections        = 96
)

type thunkKey struct {
	dll string
	rva uint32
}

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
	exportBase int64
	nameBytes  int
	walked     map[thunkKey]bool
	done       <-chan struct{}

	dirs              []pe.DataDirectory
	overlayOffset     int64
	overlaySize       int64
	resourcesParsed   bool
	resources         []peResource
	resourceTimestamp int64
	hasResourceDir    bool
	versionInfo       map[string]string
	versionList       []versionEntry
	versionParsed     map[uint32]bool
	imphashValue      string
	imphashDone       bool
	signaturesParsed  bool
	signatures        []peSignature
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
	steps    int   // for loop iterations so far, see maxLoopSteps
	err      error // why the scan stopped evaluating, if it did
	funcs    map[funcKey]any
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

// noSymbols hides the COFF symbol table fields (PointerToSymbolTable and
// NumberOfSymbols) from debug/pe, which rejects the file when they are garbage.
// libyara never reads the symbol table.
type noSymbols struct {
	r   *bytes.Reader
	buf []byte
}

func (n noSymbols) ReadAt(p []byte, off int64) (int, error) {
	c, err := n.r.ReadAt(p, off)
	if len(n.buf) < 0x40 {
		return c, err
	}
	start := int64(binary.LittleEndian.Uint32(n.buf[0x3c:])) + 4 + 8
	for i := max(off, start); i < min(off+int64(c), start+8); i++ {
		p[i-off] = 0
	}
	return c, err
}

func parsePE(buf []byte, done <-chan struct{}) *peInfo {
	if len(buf) < 0x40 || buf[0] != 'M' || buf[1] != 'Z' {
		return nil
	}
	f, err := pe.NewFile(noSymbols{r: bytes.NewReader(buf), buf: buf})
	if err != nil {
		return nil
	}
	info := &peInfo{file: f, buf: buf, chars: int64(f.Characteristics), walked: map[thunkKey]bool{}, done: done}
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
	info.dirs = dirs
	info.parseOverlay()
	if len(dirs) > 1 {
		info.parseExports(dirs[0])
		info.parseImports(dirs[1])
	}
	return info
}

func (p *peInfo) parseOverlay() {
	var highestOffset, highestSize uint64
	for _, s := range p.file.Sections[:min(len(p.file.Sections), maxPESections)] {
		if end := uint64(s.Offset) + uint64(s.Size); end > highestOffset+highestSize {
			highestOffset, highestSize = uint64(s.Offset), uint64(s.Size)
		}
	}
	if end := highestOffset + highestSize; end != 0 && uint64(len(p.buf)) > end {
		p.overlayOffset, p.overlaySize = int64(end), int64(uint64(len(p.buf))-end)
	}
}

func (p *peInfo) rvaToOffset(rva uint32) (int, bool) {
	for _, s := range p.file.Sections {
		if rva >= s.VirtualAddress && rva-s.VirtualAddress < s.Size {
			off := uint64(s.Offset&^0x1FF) + uint64(rva-s.VirtualAddress)
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
	p.exportBase = int64(first)
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
		key := thunkKey{dll: strings.ToLower(dll), rva: thunks}
		if p.walked[key] {
			continue
		}
		p.walked[key] = true
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
			ordinal := uint16(v)
			name := lookupOrdinal(dll, ordinal)
			if name == "" {
				name = "ord" + strconv.Itoa(int(ordinal))
			}
			p.imports = append(p.imports, peImport{dll: dll, name: name, ordinal: int64(ordinal), byOrdinal: true})
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
	if p.imphashDone {
		return p.imphashValue
	}
	p.imphashDone = true
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
		sb.WriteString(strings.ToLower(imp.name))
	}
	sum := md5.Sum([]byte(sb.String()))
	p.imphashValue = hex.EncodeToString(sum[:])
	return p.imphashValue
}

var peConstants = map[string]int64{
	"pe.RELOCS_STRIPPED": 0x1, "pe.EXECUTABLE_IMAGE": 0x2, "pe.LINE_NUMS_STRIPPED": 0x4,
	"pe.LOCAL_SYMS_STRIPPED": 0x8, "pe.LARGE_ADDRESS_AWARE": 0x20, "pe.32BIT_MACHINE": 0x100,
	"pe.DEBUG_STRIPPED": 0x200, "pe.SYSTEM": 0x1000, "pe.DLL": 0x2000,
	"pe.MACHINE_UNKNOWN": 0, "pe.MACHINE_I386": 0x14c, "pe.MACHINE_AMD64": 0x8664,
	"pe.MACHINE_ARM": 0x1c0, "pe.MACHINE_ARM64": 0xaa64,
	"pe.SUBSYSTEM_NATIVE": 1, "pe.SUBSYSTEM_WINDOWS_GUI": 2, "pe.SUBSYSTEM_WINDOWS_CUI": 3,
	"pe.SUBSYSTEM_EFI_APPLICATION": 10,
	"pe.RESOURCE_TYPE_CURSOR":      1, "pe.RESOURCE_TYPE_BITMAP": 2, "pe.RESOURCE_TYPE_ICON": 3,
	"pe.RESOURCE_TYPE_MENU": 4, "pe.RESOURCE_TYPE_DIALOG": 5, "pe.RESOURCE_TYPE_STRING": 6,
	"pe.RESOURCE_TYPE_FONTDIR": 7, "pe.RESOURCE_TYPE_FONT": 8, "pe.RESOURCE_TYPE_ACCELERATOR": 9,
	"pe.RESOURCE_TYPE_RCDATA": 10, "pe.RESOURCE_TYPE_MESSAGETABLE": 11, "pe.RESOURCE_TYPE_GROUP_CURSOR": 12,
	"pe.RESOURCE_TYPE_GROUP_ICON": 14, "pe.RESOURCE_TYPE_VERSION": 16, "pe.RESOURCE_TYPE_DLGINCLUDE": 17,
	"pe.RESOURCE_TYPE_PLUGPLAY": 19, "pe.RESOURCE_TYPE_VXD": 20, "pe.RESOURCE_TYPE_ANICURSOR": 21,
	"pe.RESOURCE_TYPE_ANIICON": 22, "pe.RESOURCE_TYPE_HTML": 23, "pe.RESOURCE_TYPE_MANIFEST": 24,
}

var peScalars = map[string]bool{
	"pe.machine": true, "pe.timestamp": true, "pe.characteristics": true, "pe.subsystem": true,
	"pe.entry_point": true, "pe.image_base": true, "pe.dll_characteristics": true,
	"pe.number_of_sections": true, "pe.number_of_exports": true,
	"pe.number_of_resources": true, "pe.resource_timestamp": true, "pe.number_of_version_infos": true,
	"pe.number_of_signatures": true, "pe.overlay.offset": true, "pe.overlay.size": true, "pe.is_pe": true,
}

var peResourceFields = map[string]bool{
	"rva": true, "offset": true, "length": true, "type": true, "id": true, "language": true,
	"type_string": true, "name_string": true, "language_string": true,
}

var peSignatureFields = map[string]bool{
	"thumbprint": true, "issuer": true, "subject": true, "version": true, "serial": true,
	"not_before": true, "not_after": true, "number_of_certificates": true,
}

var peVersionListFields = map[string]bool{"key": true, "value": true}

var peArrayFields = map[string]map[string]bool{
	"pe.sections":          peSectionFields,
	"pe.resources":         peResourceFields,
	"pe.version_info_list": peVersionListFields,
	"pe.signatures":        peSignatureFields,
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
		return ok && peArrayFields[id.Name][e.Name]
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
	case "pe.overlay.offset":
		return p.overlayOffset
	case "pe.overlay.size":
		return p.overlaySize
	case "pe.is_pe":
		return int64(1)
	case "pe.number_of_resources":
		p.ensureResources()
		return int64(len(p.resources))
	case "pe.resource_timestamp":
		p.ensureResources()
		if !p.hasResourceDir {
			return nil
		}
		return p.resourceTimestamp
	case "pe.number_of_signatures":
		p.ensureSignatures()
		return int64(len(p.signatures))
	case "pe.number_of_version_infos":
		p.ensureResources()
		return int64(len(p.versionList))
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
		switch a := args[0].(type) {
		case string:
			for i, s := range p.file.Sections {
				if s.Name == a {
					return int64(i)
				}
			}
		case int64:
			for i, s := range p.file.Sections[:min(len(p.file.Sections), maxPESections)] {
				if a >= int64(s.Offset) && a < int64(s.Offset)+int64(s.Size) {
					return int64(i)
				}
			}
		}
		return nil
	case "pe.exports":
		switch a := args[0].(type) {
		case string:
			for _, e := range p.exports {
				if e.name == a {
					return true
				}
			}
		case int64:
			return a >= p.exportBase && a-p.exportBase < p.numExports
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
			if imp.name == fn {
				return int64(1)
			}
		case int64:
			if imp.byOrdinal && imp.ordinal == fn {
				return int64(1)
			}
		}
	}
	return n
}
