// +build !windows,!linux

package main

import (
	"fmt"
	"os"
)

func checkPermissions() error {
	if uid := os.Getuid(); uid != 0 {
		return fmt.Errorf("gof5 needs to run as root")
	}
	return nil
}
