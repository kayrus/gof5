// +build windows

package config

import (
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

const (
	winTun     = "wintun.dll"
	winTunSite = "https://www.wintun.net/"
)

func checkWinTunDriver() error {
	err := windows.NewLazyDLL(winTun).Load()
	if err != nil {
		dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
		if err != nil {
			dir = "gof5"
		}
		return fmt.Errorf("the %s was not found, you can download it from %s and place it into the %q directory", winTun, winTunSite, dir)
	}

	return nil
}
