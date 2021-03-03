// +build darwin freebsd

package tun

import (
	"fmt"
	"net"
	"os/exec"

	"golang.zx2c4.com/wireguard/tun"
)

func setInterface(tun *tun.NativeTun, local, gw *net.IPNet) error {
	name, err := tun.Name()
	if err != nil {
		return err
	}

	args := []string{
		name,
		"inet",
		local.String(),
		gw.IP.String(),
	}
	v, err := exec.Command("ifconfig", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set ip addr: %s: %s: %s", args, v, err)
	}
	args = []string{
		name,
		"up",
	}
	v, err = exec.Command("ifconfig", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to bring up interface: %s: %s: %s", args, v, err)
	}

	return nil
}
