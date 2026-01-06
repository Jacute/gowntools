package binutils

import "debug/macho"

type machoBinary struct {
	info *binaryInfo
}

func (bin *machoBinary) Info() *binaryInfo {
	return bin.info
}

func (bin *machoBinary) GetSymbolAddr(symbolName string) (Addr, error) {
	panic("not implemented")
}

func (bin *machoBinary) GetStringAddr(s string) (Addr, error) {
	panic("not implemented")
}

func (bin *machoBinary) GetGadgetAddr(instructions []string) ([]Addr, error) {
	panic("not implemented")
}

func scanMacho(f *macho.File) (bin Binary, err error) {
	bin = &machoBinary{
		info: &binaryInfo{
			OS:        OSMac,
			Arch:      machoArch(f.Cpu),
			ByteOrder: f.ByteOrder,
			Security: &SecurityInfo{
				RelRo: RelRoUnknown,
			},
		},
	}
	// TODO: scan linking, compiler, security, etc
	return bin, nil
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
