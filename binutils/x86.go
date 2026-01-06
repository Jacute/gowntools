package binutils

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/arch/x86/x86asm"
)

func assembleX86(instructions []string) ([]byte, error) {
	src := "BITS 64\n" + strings.Join(instructions, "\n") + "\n"

	dir, err := os.MkdirTemp("", "asm")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)

	asmPath := filepath.Join(dir, "code.asm")
	binPath := filepath.Join(dir, "code.bin")

	if err := os.WriteFile(asmPath, []byte(src), 0644); err != nil {
		return nil, err
	}

	cmd := exec.Command("nasm", "-f", "bin", asmPath, "-o", binPath)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("nasm error: %v\n%s", err, out)
	}

	return os.ReadFile(binPath)
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
