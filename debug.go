package pwn

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

const attachTimeout = 10 * time.Second

var (
	ErrTerminalNotFound = errors.New("can't get terminal")
)

var (
	TmuxTerminal  = []string{"tmux", "splitw", "-h"}
	XtermTerminal = []string{"xterm", "-e"}
	GnomeTerminal = []string{"gnome-terminal", "--"}
)

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
	terminal, err := getTerminal()
	if err != nil {
		return fmt.Errorf("can't get terminal for spawn gdb")
	}

	args := append(terminal[1:], gdbCmd...)
	cmd := exec.Command(terminal[0], args...)

	err = cmd.Start()
	if err != nil {
		return err
	}

	err = waitForAttach(bin.Pid(), attachTimeout)
	if err != nil {
		return err
	}

	return nil
}

func getTerminal() ([]string, error) {
	gnomeEnv := os.Getenv("GNOME_TERMINAL_SCREEN")
	if gnomeEnv != "" {
		return GnomeTerminal, nil
	}
	tmuxEnv := os.Getenv("TMUX")
	if tmuxEnv != "" {
		return TmuxTerminal, nil
	}
	termEnv := os.Getenv("TERM")
	if strings.HasPrefix(termEnv, "xterm") {
		return XtermTerminal, nil
	}
	return nil, ErrTerminalNotFound
}

func waitForAttach(pid int, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
		if err != nil {
			return err
		}

		if strings.Contains(string(data), "TracerPid:\t0") {
			time.Sleep(50 * time.Millisecond)
			continue
		}

		return nil // attached
	}

	return fmt.Errorf("timeout waiting for gdb attach")
}
