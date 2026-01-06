package binutils

import (
	"bytes"
	"debug/elf"
	"fmt"
	"io"

	"golang.org/x/arch/x86/x86asm"
)

func scanELF(f *elf.File) (info *Binary, err error) {
	info = &Binary{
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

	dynamic, err := getELFSection(f.Sections, ".dynamic")
	if dynamic == nil && err != nil {
		info.StaticLinking = true
	}
	info.dataSections = getELFDataSections(f)

	symbols, err := loadELFSymbols(f, info.StaticLinking)
	if err != nil {
		return nil, err
	}
	info.symbols = symbols

	gadgets, err := loadELFGadgets(f, info.Arch)
	if err != nil {
		return nil, err
	}
	info.gadgets = gadgets

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
func getELFSection(sections []*elf.Section, name string) (*elf.Section, error) {
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

func loadELFGadgets(f *elf.File, arch Arch) (map[Gadget][]Addr, error) {
	const gadgetTerminatorOp = x86asm.RET // "ret" instruction
	const gadgetTerminatorOpcode = '\xc3' // TODO: add other ret terminators

	gadgets := make(map[Gadget][]Addr)
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD || (p.Flags&elf.PF_X) == 0 {
			continue
		}

		r := p.Open()
		code, err := io.ReadAll(r)
		if err != nil {
			return nil, err
		}

		for i := range code {
			if code[i] != gadgetTerminatorOpcode {
				continue
			}

			for j := 0; j < maxGadgetLen && j <= i; j++ {
				buf := make([]byte, j+1)
				copy(buf, code[i-j:i+1])

				gadget := [maxGadgetLen]x86asm.Inst{}
				instLen := 0
				for len(buf) > 0 {
					inst, err := x86asm.Decode(buf, int(arch.Bitness))
					if err != nil {
						buf = buf[1:]
						continue
					}
					buf = buf[inst.Len:]
					gadget[instLen] = inst
					instLen++
				}

				g := Gadget{
					Insts: gadget,
					Len:   instLen,
				}
				addr := Addr(p.Vaddr + uint64(i-j))

				if _, ok := gadgets[g]; !ok {
					gadgets[g] = make([]Addr, 0)
				}
				gadgets[g] = append(gadgets[g], addr)
			}
		}
	}

	return gadgets, nil
}

func getELFDataSections(f *elf.File) []*elf.Section {
	dataSections := make([]*elf.Section, 0)
	for _, sec := range f.Sections {
		if sec.Name == ".data" || sec.Name == ".rodata" {
			dataSections = append(dataSections, sec)
		}
	}

	return dataSections
}

func findStringInELFSection(section *elf.Section, str string) (Addr, error) {
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

func readFirstInstructionsX86(code []byte, bitness int, n int) []x86asm.Inst {
	insts := make([]x86asm.Inst, 0, n)

	offset := 0
	for len(code) > 0 && len(insts) < n {
		inst, err := x86asm.Decode(code, bitness)
		if err != nil {
			code = code[1:]
			offset++
			continue
		}
		insts = append(insts, inst)
		code = code[inst.Len:]
		offset += inst.Len
	}

	return insts
}
