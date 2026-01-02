package binary

import (
	"bufio"
	"debug/elf"
	"encoding/binary"
	"errors"
	"io"
)

var ErrNoDynamicSection = errors.New("no .dynamic section")

type RelRo uint8

const (
	RelRoEnable RelRo = iota
	RelRoPartial
	RelRoDisable
	RelRoUnknown
)

func (r RelRo) String() string {
	switch r {
	case RelRoEnable:
		return "enable"
	case RelRoPartial:
		return "partial"
	case RelRoDisable:
		return "disable"
	default:
		return "unknown"
	}
}

type SecurityInfo struct {
	RelRo        RelRo
	CanaryEnable bool
	NXEnable     bool
	PIEEnable    bool
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

func scanRelRo(f *elf.File, dynamic *elf.Section, order binary.ByteOrder) (RelRo, error) {
	ptGnuRelRoEnable := false
	for _, prog := range f.Progs {
		if prog.Type == elf.PT_GNU_RELRO {
			ptGnuRelRoEnable = true
			break
		}
	}

	if !ptGnuRelRoEnable {
		return RelRoDisable, nil
	}

	if dynamic == nil {
		return RelRoPartial, nil
	}

	r := bufio.NewReader(dynamic.Open())

	for {
		var dyn elf.Dyn64
		if err := binary.Read(r, order, &dyn); err != nil {
			if err == io.EOF {
				break
			}
			return RelRoUnknown, err
		}

		if dyn.Tag == int64(elf.DT_FLAGS) && dyn.Val&uint64(elf.DF_BIND_NOW) != 0 {
			return RelRoEnable, nil
		}
	}

	return RelRoPartial, nil
}
