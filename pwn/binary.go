package pwn

import (
	"errors"
	"io"
	"os/exec"
	"syscall"
)

var (
	errIncorrectClient = errors.New("client should has pwn.Binary type")
)

type Binary struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	stderr io.ReadCloser
}

// NewBinary creates a new binary client given a path to a binary.
// It returns a new client from the given binary.
// Function panics on error.
func NewBinary(path string) Client {
	cmd := exec.Command(path)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		panic(err)
	}

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		panic(err)
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		panic(err)
	}

	err = cmd.Start()
	if err != nil {
		panic(err)
	}

	return &Conn{
		conn: &Binary{
			cmd:    cmd,
			stdin:  stdin,
			stdout: stdout,
			stderr: stderr,
		},
	}
}

func (bn *Binary) Read(b []byte) (n int, err error) {
	return bn.stdout.Read(b)
}

func (bn *Binary) Write(b []byte) (n int, err error) {
	return bn.stdin.Write(b)
}

func (bn *Binary) Close() error {
	bn.stdin.Close()
	bn.stdout.Close()
	bn.stderr.Close()
	return bn.cmd.Process.Signal(syscall.SIGINT)
}

func (bn *Binary) Pid() int {
	return bn.cmd.Process.Pid
}
