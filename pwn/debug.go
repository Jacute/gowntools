package pwn

import (
	"fmt"
	"os/exec"
)

var (
	TmuxTerminal  = []string{"tmux", "splitw", "-h"}
	XtermTerminal = []string{"xterm", "-e"}
)

var Terminal = XtermTerminal

func Debug(client Client) error {
	conn, ok := client.(*Conn)
	if !ok {
		return errIncorrectClient
	}

	bin, ok := conn.conn.(*Binary)
	if !ok {
		return errIncorrectClient
	}

	gdbCmd := []string{
		"gdb",
		"-q",
		"-p",
		fmt.Sprintf("%d", bin.Pid()),
	}

	// terminal + gdb
	args := append(Terminal[1:], gdbCmd...)
	cmd := exec.Command(Terminal[0], args...)

	err := cmd.Start()
	if err != nil {
		return err
	}

	return cmd.Wait()
}
