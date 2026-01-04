package binutils

import (
	"bytes"
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

var (
	ErrUnknownArch    = errors.New("unknown arch")
	ErrUnknownOS      = errors.New("unknown os")
	ErrUnknownBinary  = errors.New("binary type is unknown")
	ErrStringNotFound = errors.New("string not found")
)

type OS string

var (
	OSLinux   OS = "Linux"
	OSWindows OS = "Windows"
	OSMac     OS = "macOS"
	OSUnknown OS = "Unknown"
)

func (o *OS) String() string {
	return string(*o)
}

type Arch struct {
	Name    string
	Bitness uint8
}

var (
	ArchAmd64   = Arch{Name: "amd64", Bitness: 64}
	ArchI386    = Arch{Name: "i386", Bitness: 32}
	ArchArm64   = Arch{Name: "arm64", Bitness: 64}
	ArchArm32   = Arch{Name: "arm", Bitness: 32}
	ArchUnknown = Arch{Name: "unknown"}
)

func (a *Arch) String() string {
	return a.Name
}

type Addr uint64

func (a Addr) String() string {
	return fmt.Sprintf("0x%x", uint64(a))
}

type Info struct {
	symbols      map[string]*elf.Symbol
	dataSections []*elf.Section

	Arch          Arch
	OS            OS
	Compiler      string
	StaticLinking bool
	ByteOrder     binary.ByteOrder
	Security      *SecurityInfo
	// Packer string
	// Language string
	// Compiler string
}

func (bi *Info) String() string {
	var builder strings.Builder

	builder.WriteString("=== BINARY INFO ===\n")

	builder.WriteString("arch: ")
	builder.WriteString(bi.Arch.String())
	builder.WriteByte('\n')

	builder.WriteString("os: ")
	builder.WriteString(bi.OS.String())
	builder.WriteByte('\n')

	builder.WriteString("compiler: ")
	builder.WriteString(bi.Compiler)
	builder.WriteByte('\n')

	builder.WriteString("linking: ")
	if bi.StaticLinking {
		builder.WriteString("static\n")
	} else {
		builder.WriteString("dynamic\n")
	}

	builder.WriteString("=== SECURITY ===\n")
	if bi.Security == nil {
		builder.WriteString("unknown\n")
		return builder.String()
	}

	builder.WriteString("relro: ")
	builder.WriteString(bi.Security.RelRo.String())
	builder.WriteByte('\n')

	fmt.Fprintf(&builder, "canary: %t\n", bi.Security.CanaryEnable)
	fmt.Fprintf(&builder, "pie: %t\n", bi.Security.PIEEnable)
	fmt.Fprintf(&builder, "nx: %t\n", bi.Security.NXEnable)

	return builder.String()
}

// AnalyzeBinary analyzes the given binary and returns information about it.
//
// The path must be a valid ELF, PE or Mach-O file. If the file is not
// recognized, an error of type ErrUnknownBinary is returned.
//
// The returned Info contains information about the binary's architecture,
// operating system, compiler, linking, and security.
//
// The returned error is nil if the analysis is successful, or an error
// describing the problem if the analysis fails.
func AnalyzeBinary(path string) (*Info, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}

	var info *Info
	var openErr error
	if ef, err := elf.Open(path); err == nil {
		info, openErr = scanELF(ef)
	} else if pf, err := pe.Open(path); err == nil {
		info, openErr = scanPE(pf)
	} else if mf, err := macho.Open(path); err == nil {
		info, openErr = scanMacho(mf)
	} else {
		return nil, ErrUnknownBinary
	}

	if openErr != nil {
		return nil, openErr
	}

	return info, nil
}

// GetSymbolAddr returns the address of the symbol with the given name.
// If the symbol is not found, an error is returned.
func (bi *Info) GetSymbolAddr(symbolName string) (Addr, error) {
	symbol, ok := bi.symbols[symbolName]
	if !ok {
		return 0, fmt.Errorf("symbol %s not found", symbolName)
	}

	return Addr(symbol.Value), nil
}

// GetStringAddr returns the address of the given string in the binary's .data or .rodata
// sections. If the string is not found, an error of type ErrStringNotFound
// is returned.
func (bi *Info) GetStringAddr(s string) (Addr, error) {
	for _, sec := range bi.dataSections {
		addr, err := findStringInSection(sec, s)
		if err != nil {
			if err == ErrStringNotFound {
				continue
			}
			return 0, err
		}
		return addr, nil
	}
	return 0, ErrStringNotFound
}

func elfArch(m elf.Machine) Arch {
	switch m {
	case elf.EM_X86_64:
		return ArchAmd64
	case elf.EM_386:
		return ArchI386
	case elf.EM_AARCH64:
		return ArchArm64
	case elf.EM_ARM:
		return ArchArm32
	default:
		return ArchUnknown
	}
}

func peArch(m uint16) Arch {
	switch m {
	case pe.IMAGE_FILE_MACHINE_AMD64:
		return ArchAmd64
	case pe.IMAGE_FILE_MACHINE_I386:
		return ArchI386
	case pe.IMAGE_FILE_MACHINE_ARM64:
		return ArchArm64
	case pe.IMAGE_FILE_MACHINE_ARM:
		return ArchArm32
	default:
		return ArchUnknown
	}
}

func machoArch(c macho.Cpu) Arch {
	switch c {
	case macho.CpuAmd64:
		return ArchAmd64
	case macho.Cpu386:
		return ArchI386
	case macho.CpuArm64:
		return ArchAmd64
	case macho.CpuArm:
		return ArchArm32
	default:
		return ArchUnknown
	}
}

func scanELF(f *elf.File) (info *Info, err error) {
	info = &Info{
		OS:        OSLinux,
		Arch:      elfArch(f.Machine),
		ByteOrder: f.ByteOrder,
		Security: &SecurityInfo{
			RelRo: RelRoUnknown,
		},
	}

	var compiler string
	for _, sec := range f.Sections {
		if sec.Name == ".comment" {
			f := sec.Open()
			data, err := io.ReadAll(f)
			if err != nil {
				return nil, err
			}
			compiler = string(data)
			if compiler[len(compiler)-1] == '\x00' {
				compiler = compiler[:len(compiler)-1]
			}
			break
		}
	}
	info.Compiler = compiler

	dynamic, err := getSection(f.Sections, ".dynamic")
	if dynamic == nil && err != nil {
		info.StaticLinking = true
	}
	info.dataSections = getDataSections(f.Sections)

	symbols, err := loadELFSymbols(f, info.StaticLinking)
	if err != nil {
		return nil, err
	}
	info.symbols = symbols

	info.Security.RelRo, err = scanRelRo(f, dynamic, info.ByteOrder)
	if err != nil {
		return nil, err
	}
	info.Security.PIEEnable = f.Type == elf.ET_DYN
	if _, ok := symbols["__stack_chk_fail"]; ok {
		info.Security.CanaryEnable = true
	}
	info.Security.NXEnable = isNXEnable(f.Progs)

	return info, nil
}

func scanPE(f *pe.File) (info *Info, err error) {
	info = &Info{
		OS:        OSWindows,
		Arch:      peArch(f.Machine),
		ByteOrder: binary.LittleEndian,
		Security: &SecurityInfo{
			RelRo: RelRoUnknown,
		},
	}
	// TODO: scan linking, compiler, security, etc
	return info, nil
}

func scanMacho(f *macho.File) (info *Info, err error) {
	info = &Info{
		OS:        OSMac,
		Arch:      machoArch(f.Cpu),
		ByteOrder: f.ByteOrder,
		Security: &SecurityInfo{
			RelRo: RelRoUnknown,
		},
	}
	// TODO: scan linking, compiler, security, etc
	return info, nil
}

func getSection(sections []*elf.Section, name string) (*elf.Section, error) {
	for _, sec := range sections {
		if sec.Name == name {
			return sec, nil
		}
	}
	return nil, fmt.Errorf("section with name %s not found", name)
}

func loadELFSymbols(f *elf.File, staticLinking bool) (map[string]*elf.Symbol, error) {
	symbols := make(map[string]*elf.Symbol)

	var syms []elf.Symbol

	syms, _ = f.Symbols() // skip error if symbols not found
	if !staticLinking {
		dynSyms, err := f.DynamicSymbols()
		if err != nil {
			return nil, err
		}
		syms = append(syms, dynSyms...)
	}

	for i := range syms {
		s := syms[i]
		symbols[syms[i].Name] = &s
	}

	return symbols, nil
}

func getDataSections(sections []*elf.Section) []*elf.Section {
	dataSections := make([]*elf.Section, 0)
	for _, sec := range sections {
		if sec.Name == ".data" || sec.Name == ".rodata" {
			dataSections = append(dataSections, sec)
		}
	}

	return dataSections
}

func findStringInSection(section *elf.Section, str string) (Addr, error) {
	data, err := section.Data()
	if err != nil {
		return 0, err
	}

	stringBytes := append([]byte(str), '\x00')
	for i := range data {
		if bytes.Equal(data[i:i+len(stringBytes)], stringBytes) {
			addr := Addr(section.Addr + uint64(i))
			return addr, nil
		}
	}

	var nilAddr Addr
	return nilAddr, ErrStringNotFound
}
