package binary

import (
	"debug/elf"
	"debug/macho"
	"debug/pe"
	"errors"
	"fmt"
	"io"
)

var (
	ErrUnknownArch = errors.New("unknown arch")
	ErrUnknownOS   = errors.New("unknown os")
)

type OS string

var (
	OSLinux   OS = "Linux"
	OSWindows OS = "Windows"
	OSMac     OS = "macOS"
	OSUnknown OS = "Unknown"
)

type Arch string

var (
	ArchAmd64   Arch = "amd64"
	ArchI386    Arch = "i386"
	ArchArm64   Arch = "arm64"
	ArchArm32   Arch = "arm"
	ArchUnknown Arch = "Unknown"
)

type BinaryInfo struct {
	Arch          Arch
	OS            OS
	Compiler      string
	StaticLinking bool
	Security      *SecurityInfo
	// Packer string
	// Language string
	// Compiler string
}

func (bi *BinaryInfo) String() string {
	return fmt.Sprintf(
		"=== BINARY INFO ===\narch: %s\nos: %s\ncompiler: %s\nstatic linking: %t\n%s",
		bi.Arch, bi.OS, bi.Compiler, bi.StaticLinking, bi.Security,
	)
}

func AnalyzeBinary(path string) (*BinaryInfo, error) {
	arch := ArchUnknown
	os := OSUnknown
	var security *SecurityInfo
	var compiler string
	var staticLinking bool

	if ef, err := elf.Open(path); err == nil {
		os = OSLinux
		arch = elfArch(ef.Machine)
		security, compiler, staticLinking, err = scanELF(ef)
		if err != nil {
			return nil, err
		}
	} else if pf, err := pe.Open(path); err == nil {
		os = OSWindows
		arch = peArch(pf.Machine)
		security, compiler, staticLinking, err = scanPE(pf)
		if err != nil {
			return nil, err
		}
	} else if mf, err := macho.Open(path); err == nil {
		os = OSMac
		arch = machoArch(mf.Cpu)
		security, compiler, staticLinking, err = scanMacho(mf)
		if err != nil {
			return nil, err
		}
	}

	return &BinaryInfo{
		Arch:          arch,
		OS:            os,
		Compiler:      compiler,
		StaticLinking: staticLinking,
		Security:      security,
	}, nil
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

func scanELF(f *elf.File) (security *SecurityInfo, compiler string, staticLinkingEnable bool, err error) {
	for _, sec := range f.Sections {
		if sec.Name == ".comment" {
			f := sec.Open()
			data, err := io.ReadAll(f)
			if err != nil {
				return nil, "", false, err
			}
			compiler = string(data)
			if compiler[len(compiler)-1] == '\x00' {
				compiler = compiler[:len(compiler)-1]
			}
			break
		}
	}

	staticLinkingEnable = f.Type != elf.ET_DYN
	security, err = scanELFSecurity(f)
	if err != nil {
		return nil, "", false, err
	}

	return security, compiler, staticLinkingEnable, nil
}

func scanPE(f *pe.File) (security *SecurityInfo, compiler string, staticLinking bool, err error) {
	panic("not implemented")
}

func scanMacho(f *macho.File) (security *SecurityInfo, compiler string, staticLinking bool, err error) {
	panic("not implemented")
}

func symbolsContains(symbols []elf.Symbol, name string) bool {
	for _, s := range symbols {
		if s.Name == name {
			return true
		}
	}
	return false
}
