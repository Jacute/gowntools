//go:build !ci

package pwn

import (
	"os"
	"testing"
	"time"

	"github.com/Jacute/gowntools/testsuite"
	"github.com/stretchr/testify/require"
)

func TestDebug(t *testing.T) {
	t.Run("ok", func(tt *testing.T) {
		c := NewBinary("./testdata/readwritetest/main")
		require.NotPanics(tt, func() {
			Debug(c)
		})
	})
	t.Run("not binary client", func(tt *testing.T) {
		server, err := testsuite.NewTCPServer()
		if err != nil {
			tt.Fatalf("failed to create tcp server: %v", err)
		}
		tt.Cleanup(func() {
			server.Close()
		})
		c := NewTCP(server.Address())

		require.Panics(tt, func() {
			Debug(c)
		})
	})
}

func TestDebug_NoGDB(t *testing.T) {
	oldPath := os.Getenv("PATH")
	t.Setenv("PATH", "")

	c := NewBinary("./testdata/readwritetest/main")

	require.Panics(t, func() {
		Debug(c)
	})

	t.Setenv("PATH", oldPath)
}

func TestDebug_NoTerminal(t *testing.T) {
	t.Setenv("GNOME_TERMINAL_SCREEN", "")
	t.Setenv("TMUX", "")
	t.Setenv("TERM", "dumb")

	c := NewBinary("./testdata/readwritetest/main")

	require.PanicsWithError(t, ErrTerminalNotFound.Error(), func() {
		Debug(c)
	})
}

func TestDebug_WithGDBScript(t *testing.T) {
	dbg := &debugger{}
	dbg.gdbCommands = []string{"break main", "continue"}

	args := dbg.buildGDBcmd()

	require.Contains(t, args, "-ex")
	require.Contains(t, args, "break main")
}

func TestWaitForAttach(t *testing.T) {
	dbg := debugger{attachPid: os.Getpid()}
	err := dbg.waitForAttach(time.Millisecond * 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), "timeout")
}
