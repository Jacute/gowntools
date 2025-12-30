package gdb

import (
	"errors"
	"fmt"
	"os/exec"
	"reflect"

	"github.com/Jacute/gowntools/pwn"
)

var (
	errIncorrectClient = errors.New("client should has pwn.Binary type")
)

func Debug(client pwn.Client) error {
	bin, err := getBinary(reflect.ValueOf(client))
	if err != nil {
		return err
	}

	cmd := exec.Command("xterm", "-e", fmt.Sprintf("gdb -p %d", bin.Pid()))

	if err := cmd.Start(); err != nil {
		return err
	}

	return nil
}

func getBinary(tp reflect.Value) (*pwn.Binary, error) {
	switch tp.Kind() {
	case reflect.Ptr:
		getBinary(tp.Elem())
	case reflect.Struct:
		if v, ok := tp.Interface().(*pwn.Binary); ok {
			return v, nil
		}
		return nil, errIncorrectClient
	}

	return nil, errIncorrectClient
}
