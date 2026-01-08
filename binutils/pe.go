package binutils

import (
	"debug/pe"
	"encoding/binary"
)

type peBinary struct {
	info *BinaryInfo
}

func (bin *peBinary) Info() *BinaryInfo {
	return bin.info
}

func (bin *peBinary) GetSymbolAddr(symbolName string) (Addr, error) {
	panic("not implemented")
}

func (bin *peBinary) GetStringAddr(s string) (Addr, error) {
	panic("not implemented")
}

func (bin *peBinary) GetGadgetAddr(instructions []string) ([]Addr, error) {
	panic("not implemented")
}

func scanPE(f *pe.File) (*peBinary, error) {
	bin := &peBinary{
		info: &BinaryInfo{
			OS:        OSWindows,
			Arch:      peArch(f.Machine),
			ByteOrder: binary.LittleEndian,
			Security: &SecurityInfo{
				RelRo: RelRoUnknown,
			},
		},
	}
	// TODO: scan linking, compiler, security, etc
	return bin, nil
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
