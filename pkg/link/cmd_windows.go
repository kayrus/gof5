//go:build windows
// +build windows

package link

import (
	"os/exec"

	"github.com/kayrus/gof5/pkg/config"
)

func Cmd(_ *config.Config) *exec.Cmd {
	return nil
}
