// +build !windows
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
	args := []string{
		name,
		"mtu",
		fmt.Sprintf("%d", mtu),
	}
	v, err := exec.Command("ifconfig", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set MTU: %s: %s: %s", args, v, err)
	}
	args = []string{
		name,
		"inet",
		util.GetNet(local).String(),
		server.String(),
	}
	v, err = exec.Command("ifconfig", args...).CombinedOutput()
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
	v, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add %s route to %s interface: %s: %s: %s", dst, name, args, v, err)
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
	v, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete %s route from %s interface: %s: %s: %s", dst, name, args, v, err)
	}
	return nil
}
