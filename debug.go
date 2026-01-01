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

type terminal []string

var (
	TmuxTerminal  = terminal{"tmux", "splitw", "-h"}
	XtermTerminal = terminal{"xterm", "-e"}
	GnomeTerminal = terminal{"gnome-terminal", "--"}
)

type debugger struct {
	term      terminal
	attachPid int
}

type option func(*debugger)

// Debug starts a gdb debugging session for the given client.
// It returns an error if the client is not a *conn or if the underlying
// process is not a *bin. The function also returns an error if it can't spawn
// a terminal to attach to the process or if the process hasn't attached to
// gdb after the given timeout.
//
// The function try to use terminals of different types (tmux, xterm, gnome-terminal)
func Debug(client Client, opts ...option) error {
	// get bin from interface Client
	conn, ok := client.(*conn)
	if !ok {
		return errIncorrectClient
	}
	bin, ok := conn.conn.(*bin)
	if !ok {
		return errIncorrectClient
	}

	// init debugger
	dbg := &debugger{
		attachPid: bin.Pid(),
	}
	for _, opt := range opts {
		opt(dbg)
	}

	// if terminal is not set by option we try to get it automatically
	if dbg.term == nil {
		terminal, err := getTerminal()
		if err != nil {
			return fmt.Errorf("can't get terminal for spawn gdb")
		}
		dbg.term = terminal
	}

	err := dbg.Start(dbg.term)
	if err != nil {
		return err
	}

	return nil
}

// WithTerminal returns an option that sets the terminal to use when spawning
// gdb to attach to the process. If this option is not used, the terminal
// is tried to be determined automatically.
func WithTerminal(term terminal) func(*debugger) {
	return func(client *debugger) {
		client.term = term
	}
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

func (d *debugger) Start(term terminal) error {
	gdbCmd := []string{
		"gdb",
		"-q",
		"-p",
		fmt.Sprintf("%d", d.attachPid),
	}

	args := append(d.term[1:], gdbCmd...)
	cmd := exec.Command(d.term[0], args...)

	err := cmd.Start()
	if err != nil {
		return err
	}

	err = d.waitForAttach(attachTimeout)
	if err != nil {
		return err
	}

	return nil
}

func (d *debugger) waitForAttach(timeout time.Duration) error {
	deadline := time.Now().Add(timeout)

	for time.Now().Before(deadline) {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", d.attachPid))
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
