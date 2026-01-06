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
	gdbCommands []string
	term        terminal
	attachPid   int
}

type option func(*debugger)

// Debug starts a gdb debugging session for the given client.
// It panics if the client is not a *conn or if the underlying
// process is not a *bin.
// The function requires gdb installed and terminal (tmux, xterm or gnome-terminal).
// Otherwise, the function will panic.
func Debug(client Client, opts ...option) {
	if _, err := exec.LookPath("gdb"); err != nil {
		panic("gdb not found in PATH")
	}

	// get bin from interface Client
	conn, ok := client.(*conn)
	if !ok {
		panic(errIncorrectClient)
	}
	bin, ok := conn.conn.(*bin)
	if !ok {
		panic(errIncorrectClient)
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
			panic(err)
		}
		dbg.term = terminal
	}

	err := dbg.start()
	if err != nil {
		panic(err)
	}
}

// WithTerminal returns an option that sets the terminal to use when spawning
// gdb to attach to the process. If this option is not used, the terminal
// is tried to be determined automatically.
func WithTerminal(term terminal) func(*debugger) {
	return func(client *debugger) {
		client.term = term
	}
}

// WithGDBScript returns an option that sets the commands to be executed
// by gdb when attaching to the process. The commands are split by newline
// characters, so the following is a valid command string:
//
//	break main\n
//	info registers\n
//	continue\n
//
// The function can be used to set arbitrary commands to be executed by
// gdb when attaching to the process. The commands are executed in the order
// they are given in the string.
func WithGDBScript(script string) func(*debugger) {
	return func(client *debugger) {
		client.gdbCommands = strings.Split(script, "\n")
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

func (d *debugger) start() error {
	gdbCmd := []string{
		"gdb",
		"-q",
	}
	if len(d.gdbCommands) != 0 {
		for _, cmd := range d.gdbCommands {
			gdbCmd = append(gdbCmd, "-ex", cmd)
		}
	}
	gdbCmd = append(gdbCmd, "-p", fmt.Sprintf("%d", d.attachPid))

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
