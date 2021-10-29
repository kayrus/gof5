//go:build !windows
// +build !windows

package config

func checkWinTunDriver() error {
	return nil
}
