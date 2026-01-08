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
	MaxGadgetLen = 20 // max count bytes in gadget
)

var (
	ErrUnknownArch    = errors.New("unknown arch")
	ErrUnknownOS      = errors.New("unknown os")
	ErrUnknownBinary  = errors.New("binary type is unknown")
	ErrStringNotFound = errors.New("string not found")
	ErrGadgetNotFound = errors.New("gadget not found")
	ErrSymbolNotFound = errors.New("symbol not found")
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

type gadget struct {
	insts [MaxGadgetLen]x86asm.Inst
	len   int
}

type BinaryInfo struct {
	Arch          Arch
	OS            OS
	Compiler      string
	Linking       string
	Security      *SecurityInfo
	StaticLinking bool
	ByteOrder     binary.ByteOrder
	// Packer string
	// Language string
}

func (bi *BinaryInfo) String() string {
	var builder strings.Builder

	builder.WriteString("=== BINARY INFO ===\n")

	builder.WriteString("Arch: ")
	builder.WriteString(bi.Arch.String())
	builder.WriteByte('\n')

	builder.WriteString("OS: ")
	builder.WriteString(bi.OS.String())
	builder.WriteByte('\n')

	builder.WriteString("Compiler: ")
	builder.WriteString(bi.Compiler)
	builder.WriteByte('\n')

	builder.WriteString("Linking: ")
	if bi.StaticLinking {
		builder.WriteString("static\n")
	} else {
		builder.WriteString("dynamic\n")
	}
	builder.WriteString("Byte Order: ")
	builder.WriteString(bi.ByteOrder.String())
	builder.WriteByte('\n')

	builder.WriteString("=== SECURITY ===\n")
	if bi.Security == nil {
		builder.WriteString("unknown\n")
		return builder.String()
	}

	builder.WriteString("RELRO: ")
	builder.WriteString(bi.Security.RelRo.String())
	builder.WriteByte('\n')

	if bi.Security.CanaryEnable {
		builder.WriteString("Canary: yes\n")
	} else {
		builder.WriteString("Canary: no\n")
	}

	if bi.Security.PIEEnable {
		builder.WriteString("PIE: yes\n")
	} else {
		builder.WriteString("PIE: no\n")
	}

	if bi.Security.NXEnable {
		builder.WriteString("NX: yes\n")
	} else {
		builder.WriteString("NX: no")
	}

	return builder.String()
}

type Binary interface {
	// Info returns binary info like arch, os, compiler, security mitigations, etc
	Info() *BinaryInfo

	// GetSymbolAddr returns the address of the symbol with the given name.
	// If the symbol is not found, an error is returned.
	GetSymbolAddr(symbolName string) (Addr, error)

	// GetStringAddr returns the address of the given string in the binary's .data or .rodata
	// sections. If the string is not found, an error of type ErrStringNotFound
	// is returned.
	GetStringAddr(s string) (Addr, error)

	GetGadgetAddr(instructions []string) ([]Addr, error)
}

// AnalyzeBinary analyzes the given binary and returns information about it.
//
// The path must be a valid ELF, PE or Mach-O file. If the file is not
// recognized, an error of type ErrUnknownBinary is returned.
//
// The returned ELF contains information about the binary's architecture,
// operating system, compiler, linking, and security.
//
// The returned error is nil if the analysis is successful, or an error
// describing the problem if the analysis fails.
func AnalyzeBinary(path string) (Binary, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}

	var bin Binary
	var openErr error
	if ef, err := elf.Open(path); err == nil {
		bin, openErr = scanELF(ef)
	} else if pf, err := pe.Open(path); err == nil {
		bin, openErr = scanPE(pf)
	} else if mf, err := macho.Open(path); err == nil {
		bin, openErr = scanMacho(mf)
	} else {
		return nil, ErrUnknownBinary
	}

	if openErr != nil {
		return nil, openErr
	}

	return bin, nil
}
