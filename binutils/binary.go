package binutils

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

const (
	maxGadgetLen = 12 // max count bytes in gadget
)

var (
	ErrUnknownArch    = errors.New("unknown arch")
	ErrUnknownOS      = errors.New("unknown os")
	ErrUnknownBinary  = errors.New("binary type is unknown")
	ErrStringNotFound = errors.New("string not found")
	ErrGadgetNotFound = errors.New("gadget not found")
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

type Gadget struct {
	Insts [maxGadgetLen]x86asm.Inst
	Len   int
}

type Binary struct {
	symbols      map[string]*elf.Symbol
	dataSections []*elf.Section
	gadgets      map[Gadget][]Addr // all gadgets in executable binary segments

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

func (bi *Binary) String() string {
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
// The returned Binary contains information about the binary's architecture,
// operating system, compiler, linking, and security.
//
// The returned error is nil if the analysis is successful, or an error
// describing the problem if the analysis fails.
func AnalyzeBinary(path string) (*Binary, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}

	var info *Binary
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
// Panics if binary isn't ELF
func (bi *Binary) GetSymbolAddr(symbolName string) (Addr, error) {
	if bi.OS != OSLinux {
		panic("GetSymbolAddr supports only ELF binaries")
	}

	symbol, ok := bi.symbols[symbolName]
	if !ok {
		return 0, fmt.Errorf("symbol %s not found", symbolName)
	}

	return Addr(symbol.Value), nil
}

// GetStringAddr returns the address of the given string in the binary's .data or .rodata
// sections. If the string is not found, an error of type ErrStringNotFound
// is returned.
// Panics if binary isn't ELF
func (bi *Binary) GetStringAddr(s string) (Addr, error) {
	if bi.OS != OSLinux {
		var nilAddr Addr
		return nilAddr, fmt.Errorf("GetStringAddr supports only ELF binaries")
	}

	for _, sec := range bi.dataSections {
		addr, err := findStringInELFSection(sec, s)
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

func (bi *Binary) GetGadgetAddr(gadget []byte) ([]Addr, error) {
	if bi.OS != OSLinux {
		return nil, fmt.Errorf("GetGadgetAddr supports only ELF binaries")
	}

	instSlice := readFirstInstructionsI386(gadget, int(bi.Arch.Bitness), maxGadgetLen)
	var instArr [maxGadgetLen]x86asm.Inst
	copy(instArr[:], instSlice)

	addrs, ok := bi.gadgets[Gadget{
		Insts: instArr,
		Len:   len(instSlice),
	}]
	if !ok {
		return nil, ErrGadgetNotFound
	}

	return addrs, nil
}

func (bi *Binary) PrintGadgets() {
	fmt.Println(bi.gadgets)
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

func scanPE(f *pe.File) (info *Binary, err error) {
	info = &Binary{
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

func scanMacho(f *macho.File) (info *Binary, err error) {
	info = &Binary{
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
