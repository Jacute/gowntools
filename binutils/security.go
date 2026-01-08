package binutils

import (
	"errors"
)

var ErrNoDynamicSection = errors.New("no .dynamic section")

type RelRo uint8

const (
	RelRoEnable RelRo = iota
	RelRoPartial
	RelRoDisable
	RelRoUnknown
)

func (r RelRo) String() string {
	switch r {
	case RelRoEnable:
		return "full"
	case RelRoPartial:
		return "partial"
	case RelRoDisable:
		return "disable"
	default:
		return "unknown"
	}
}

type SecurityInfo struct {
	RelRo        RelRo
	CanaryEnable bool
	NXEnable     bool
	PIEEnable    bool
}
