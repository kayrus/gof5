// +build !linux

package route

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/kayrus/gof5/pkg/util"

	"github.com/jackpal/gateway"
)

func SetInterface(name string, local, server net.IP, mtu int) error {
	v, err := exec.Command("ifconfig", name, "mtu", fmt.Sprintf("%d", mtu)).Output()
	if err != nil {
		return fmt.Errorf("failed to set MTU: %s: %s", v, err)
	}
	v, err = exec.Command("ifconfig", name, "inet", util.GetNet(local).String(), server.String()).Output()
	if err != nil {
		return fmt.Errorf("failed to set ip addr: %s: %s", v, err)
	}
	v, err = exec.Command("ifconfig", name, "up").Output()
	if err != nil {
		return fmt.Errorf("failed to bring up interface: %s: %s", v, err)
	}
	return nil
}

func RouteGet(dst net.IP) ([]net.IP, error) {
	v, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("failed to discover the gateway for %s: %s", dst, err)
	}
	return []net.IP{v}, nil
}

func RouteAdd(dst interface{}, gw net.IP, priority int, name string) error {
	// an implementation of "replace"
	RouteDel(dst, gw, priority, name)
	args := []string{
		"-n",
		"add",
		"-net",
		util.GetNet(dst).String(),
	}
	if gw == nil {
		args = append(args, "-interface", name)
	} else {
		args = append(args, gw.String())
	}
	v, err := exec.Command("route", args...).Output()
	if err != nil {
		return fmt.Errorf("failed to add %s route to %s interface: %s: %s", dst, name, v, err)
	}
	return nil
}

func RouteDel(dst interface{}, gw net.IP, priority int, name string) error {
	args := []string{
		"-n",
		"delete",
		"-net",
		util.GetNet(dst).String(),
	}
	if gw == nil {
		args = append(args, "-interface", name)
	} else {
		args = append(args, gw.String())
	}
	v, err := exec.Command("route", args...).Output()
	if err != nil {
		return fmt.Errorf("failed to delete %s route from %s interface: %s: %s", dst, name, v, err)
	}
	return nil
}
