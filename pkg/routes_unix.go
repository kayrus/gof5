// +build !linux

package pkg

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/jackpal/gateway"
)

func routeGet(dst net.IP) ([]net.IP, error) {
	v, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("failed to discover the gateway for %s: %s", dst, err)
	}
	return []net.IP{v}, nil
}

func routeAdd(dst interface{}, gw net.IP, priority int, iface string) error {
	// TODO: handle "Network is unreachable"
	args := []string{
		"-n",
		"add",
		"-net",
		getNet(dst).String(),
	}
	if gw == nil {
		args = append(args, "-interface", iface)
	} else {
		args = append(args, gw.String())
	}
	v, err := exec.Command("route", args...).Output()
	if err != nil {
		return fmt.Errorf("failed to add %s route to %s interface: %s: %s", dst, iface, v, err)
	}
	return nil
}

func routeDel(dst interface{}, gw net.IP, priority int, iface string) error {
	args := []string{
		"-n",
		"del",
		"-net",
		getNet(dst).String(),
	}
	if gw == nil {
		args = append(args, "-interface", iface)
	} else {
		args = append(args, gw.String())
	}
	v, err := exec.Command("route", args...).Output()
	if err != nil {
		return fmt.Errorf("failed to delete %s route from %s interface: %s: %s", dst, iface, v, err)
	}
	return nil
}
