package binary

import (
	"debug/elf"
	"errors"
	"fmt"
	"io"
)

var (
	ErrNoDynamicSection = errors.New("no .dynamic section")
)

type SecurityInfo struct {
	CanaryEnable bool
	NXEnable     bool
	PIEEnable    bool
}

func (s *SecurityInfo) String() string {
	return fmt.Sprintf("=== SECURITY INFO ===\ncanary: %v\nnx: %v\npie: %v\n", s.CanaryEnable, s.NXEnable, s.PIEEnable)
}

func scanELFSecurity(f *elf.File, staticLinking bool) (security *SecurityInfo, err error) {
	var symbols []elf.Symbol
	if staticLinking {
		symbols, err = f.Symbols()
	} else {
		symbols, err = f.DynamicSymbols()
	}
	if err != nil {
		return nil, err
	}

	security = &SecurityInfo{
		CanaryEnable: symbolsContains(symbols, "__stack_chk_fail"),
		PIEEnable:    f.Type == elf.ET_DYN,
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

func readSection(name string, sections []*elf.Section) ([]byte, error) {
	for _, sec := range sections {
		if sec.Name == name {
			data, err := io.ReadAll(sec.Open())
			if err != nil {
				return nil, err
			}
			return data, err
		}
	}
	return nil, fmt.Errorf("no section with name %s", name)
}

func sectionsContains(sections []*elf.Section, name string) bool {
	for _, sec := range sections {
		if sec.Name == name {
			return true
		}
	}
	return false
}
