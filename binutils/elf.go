package binutils

import (
	"bufio"
	"bytes"
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/arch/x86/x86asm"
)

type elfBinary struct {
	symbols      map[string]*elf.Symbol
	dataSections []*elf.Section
	gadgets      map[gadget][]Addr // all gadgets in executable binary segments

	info *BinaryInfo
}

func (bi *elfBinary) Info() *BinaryInfo {
	return bi.info
}

func (bi *elfBinary) GetSymbolAddr(symbolName string) (Addr, error) {
	symbol, ok := bi.symbols[symbolName]
	if !ok {
		return 0, fmt.Errorf("symbol %s not found", symbolName)
	}

	return Addr(symbol.Value), nil
}

func (bi *elfBinary) GetStringAddr(s string) (Addr, error) {
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

func (bi *elfBinary) GetGadgetAddr(instructions []string) ([]Addr, error) {
	gadgetBytes, err := assembleX86(instructions)
	if err != nil {
		if errors.Is(err, ErrNasmNotFoundInPATH) {
			panic(err)
		}
		return nil, err
	}

	instSlice := readFirstInstructionsX86(gadgetBytes, int(bi.info.Arch.Bitness), MaxGadgetLen)
	var instArr [MaxGadgetLen]x86asm.Inst
	copy(instArr[:], instSlice)

	addrs, ok := bi.gadgets[gadget{
		insts: instArr,
		len:   len(instSlice),
	}]
	if !ok {
		return nil, ErrGadgetNotFound
	}

	return addrs, nil
}

func scanELF(f *elf.File) (*elfBinary, error) {
	bin := &elfBinary{
		info: &BinaryInfo{
			OS:        OSLinux,
			Arch:      elfArch(f.Machine),
			ByteOrder: f.ByteOrder,
			Security: &SecurityInfo{
				RelRo: RelRoUnknown,
			},
		},
	}

	commentSec, err := getELFSection(f.Sections, ".comment")
	if err != nil {
		return nil, fmt.Errorf("error getting .comment section: %w", err)
	}
	compiler, err := getELFCompiler(commentSec)
	if err != nil {
		return nil, fmt.Errorf("error getting compiler: %w", err)
	}
	bin.info.Compiler = compiler

	dynamic, err := getELFSection(f.Sections, ".dynamic")
	if dynamic == nil && err != nil {
		bin.info.StaticLinking = true
	}
	bin.dataSections = getELFDataSections(f)

	symbols, err := loadELFSymbols(f, bin.info.StaticLinking)
	if err != nil {
		return nil, fmt.Errorf("error loading symbols: %w", err)
	}
	bin.symbols = symbols

	gadgets, err := loadELFGadgets(f.Progs, bin.info.Arch)
	if err != nil {
		return nil, fmt.Errorf("error loading gadgets: %w", err)
	}
	bin.gadgets = gadgets

	bin.info.Security.RelRo, err = scanRelRoELF(bin.info.Arch, f.Progs, dynamic, bin.info.ByteOrder)
	if err != nil {
		return nil, fmt.Errorf("error scanning relro: %w", err)
	}
	bin.info.Security.PIEEnable = f.Type == elf.ET_DYN
	if _, ok := symbols["__stack_chk_fail"]; ok {
		bin.info.Security.CanaryEnable = true
	}
	bin.info.Security.NXEnable = isNXEnableELF(f.Progs)

	return bin, nil
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

func getELFCompiler(commentSection *elf.Section) (string, error) {
	f := commentSection.Open()
	data, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("error reading .comment section to get compiler: %w", err)
	}

	compiler := string(data)
	if compiler[len(compiler)-1] == '\x00' {
		compiler = compiler[:len(compiler)-1]
	}

	return compiler, nil
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
			return nil, fmt.Errorf("error loading dynamic symbols: %w", err)
		}
		syms = append(syms, dynSyms...)
	}

	for i := range syms {
		s := syms[i]
		symbols[syms[i].Name] = &s
	}

	return symbols, nil
}

func loadELFGadgets(progs []*elf.Prog, arch Arch) (map[gadget][]Addr, error) {
	const gadgetTerminatorOp = x86asm.RET // "ret" instruction
	const gadgetTerminatorOpcode = '\xc3' // TODO: add other ret terminators

	gadgets := make(map[gadget][]Addr)
	for _, p := range progs {
		if p.Type != elf.PT_LOAD || (p.Flags&elf.PF_X) == 0 {
			continue
		}

		r := p.Open()
		code, err := io.ReadAll(r)
		if err != nil {
			return nil, fmt.Errorf("error reading program: %w", err)
		}

		for i := range code {
			if code[i] != gadgetTerminatorOpcode {
				continue
			}

			for j := 0; j < MaxGadgetLen && j <= i; j++ {
				buf := make([]byte, j+1)
				copy(buf, code[i-j:i+1])

				insts := [MaxGadgetLen]x86asm.Inst{}
				instLen := 0
				for len(buf) > 0 {
					inst, err := x86asm.Decode(buf, int(arch.Bitness))
					if err != nil {
						buf = buf[1:]
						continue
					}
					buf = buf[inst.Len:]
					insts[instLen] = inst
					instLen++
				}

				g := gadget{
					insts: insts,
					len:   instLen,
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
		return 0, fmt.Errorf("error reading section %s: %w", section.Name, err)
	}

	stringBytes := append([]byte(str), '\x00')
	for i := 0; i < len(data)-len(stringBytes); i++ {
		if bytes.Equal(data[i:i+len(stringBytes)], stringBytes) {
			addr := Addr(section.Addr + uint64(i))
			return addr, nil
		}
	}

	return 0, ErrStringNotFound
}

func isNXEnableELF(progs []*elf.Prog) bool {
	nx := true
	for _, prog := range progs {
		if prog.Type == elf.PT_GNU_STACK && prog.Flags&elf.PF_X != 0 {
			nx = false
			break
		}
	}
	return nx
}

func scanRelRoELF(arch Arch, progs []*elf.Prog, dynamic *elf.Section, order binary.ByteOrder) (RelRo, error) {
	ptGnuRelRoEnable := false
	for _, prog := range progs {
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

loop:
	for {
		switch arch {
		case ArchAmd64:
			var dyn elf.Dyn64
			if err := binary.Read(r, order, &dyn); err != nil {
				if err == io.EOF {
					break loop
				}
				return RelRoUnknown, err
			}

			if dyn.Tag == int64(elf.DT_FLAGS) && dyn.Val&uint64(elf.DF_BIND_NOW) != 0 {
				return RelRoEnable, nil
			}

		case ArchI386:
			var dyn elf.Dyn32
			if err := binary.Read(r, order, &dyn); err != nil {
				if err == io.EOF {
					break loop
				}
				return RelRoUnknown, err
			}
			if dyn.Tag == int32(elf.DT_FLAGS) && dyn.Val&uint32(elf.DF_BIND_NOW) != 0 {
				return RelRoEnable, nil
			}
		default:
			return RelRoUnknown, fmt.Errorf("unknown arch: %s", arch.Name)
		}
	}

	return RelRoPartial, nil
}
