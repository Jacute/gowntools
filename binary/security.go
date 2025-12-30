package binary

import (
	"debug/elf"
	"fmt"
)

type SecurityInfo struct {
	CanaryEnable bool
	NXEnable     bool
	PIEEnable    bool
}

func (s *SecurityInfo) String() string {
	return fmt.Sprintf("=== SECURITY INFO ===\ncanary: %v\nnx: %v\npie: %v\n", s.CanaryEnable, s.NXEnable, s.PIEEnable)
}

func scanELFSecurity(f *elf.File) (security *SecurityInfo, err error) {
	var symbols []elf.Symbol
	pie := false
	if f.Type == elf.ET_DYN {
		symbols, err = f.DynamicSymbols()
		if err != nil {
			return nil, err
		}
	} else {
		symbols, err = f.Symbols()
		if err != nil {
			return nil, err
		}
		pie = isPieEnable(f.Sections)
	}

	security = &SecurityInfo{
		CanaryEnable: symbolsContains(symbols, "__stack_chk_fail"),
		PIEEnable:    pie,
		NXEnable:     isNXEnable(f.Progs),
	}

	return security, nil
}

func isNXEnable(progs []*elf.Prog) bool {
	nx := true
	for _, prog := range progs {
		if prog.Type == elf.PT_GNU_STACK && prog.Flags&elf.PF_X != 0 {
			nx = false
			break
		}
	}
	return nx
}

func isPieEnable(sections []*elf.Section) bool {
	for _, sec := range sections {
		if sec.Name == ".dynamic" {
			fmt.Println(1, sec.Flags.GoString())
			return true
		}
	}
	return false
}
