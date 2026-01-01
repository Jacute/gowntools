package pwn

import (
	"errors"
	"io"
	"os/exec"
	"syscall"
)

var (
	errIncorrectClient = errors.New("client should has pwn.bin type")
)

type bin struct {
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

	return &conn{
		conn: &bin{
			cmd:    cmd,
			stdin:  stdin,
			stdout: stdout,
			stderr: stderr,
		},
	}
}

// Read reads data from the binary's stdout.
// It returns the number of bytes read and any error that occurred.
func (bn *bin) Read(b []byte) (n int, err error) {
	return bn.stdout.Read(b)
}

// Write writes data to the binary's stdin.
// It returns the number of bytes written and any error that occurred.
func (bn *bin) Write(b []byte) (n int, err error) {
	return bn.stdin.Write(b)
}

// Close closes all the binary's IO streams and sends a SIGINT signal to the
// underlying process.
func (bn *bin) Close() error {
	bn.stdin.Close()
	bn.stdout.Close()
	bn.stderr.Close()
	return bn.cmd.Process.Signal(syscall.SIGINT)
}

// Pid returns the process ID of the underlying process.
// It is used to identify the process when debugging.
func (bn *bin) Pid() int {
	return bn.cmd.Process.Pid
}
