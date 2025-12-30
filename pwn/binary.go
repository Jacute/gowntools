package pwn

import (
	"io"
	"os/exec"

	"github.com/creack/pty"
)

type Binary struct {
	cmd      *exec.Cmd
	terminal io.ReadWriteCloser
}

// NewBinary creates a new binary client given a path to a binary.
// It returns a new client from the given binary.
// Function panics on error.
func NewBinary(path string) Client {
	cmd := exec.Command(path)

	ptmx, err := pty.Start(cmd)
	if err != nil {
		panic(err)
	}

	return &Conn{
		conn: &Binary{
			cmd:      cmd,
			terminal: ptmx,
		},
	}
}

func (bn *Binary) Read(b []byte) (n int, err error) {
	return bn.terminal.Read(b)
}

func (bn *Binary) Write(b []byte) (n int, err error) {
	return bn.terminal.Write(b)
}

func (bn *Binary) Close() error {
	return bn.terminal.Close()
}

func (bn *Binary) Pid() int {
	return bn.cmd.Process.Pid
}
