// +build windows

package route

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/kayrus/gof5/pkg/util"

	"github.com/jackpal/gateway"
)

var ifIndex int

func SetInterface(name string, local, server net.IP, mtu int) error {
	args := []string{
		"interface",
		"ipv4",
		"set",
		"subinterface",
		name,
		fmt.Sprintf("mtu=%d", mtu),
		"store=persistent",
	}
	v, err := exec.Command("netsh.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set MTU on %s interface: %s: %s: %s", name, args, v, err)
	}

	args = []string{
		"interface",
		"ipv4",
		"set",
		"address",
		"name=" + name,
		"static",
		local.String(),
		net.IPv4(0xff, 0xff, 0xff, 0xff).To4().String(),
	}
	v, err = exec.Command("netsh.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to set tun interface: %s: %s: %s", args, v, err)
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
	var err error
	if ifIndex == 0 {
		if ifIndex, err = util.GetIfID(name); err != nil {
			return err
		}
	}

	// an implementation of "replace"
	RouteDel(dst, gw, priority, name)
	d := util.GetNet(dst)
	args := []string{
		"add",
		d.IP.String(),
		"mask",
		net.IP(d.Mask).To4().String(),
		gw.String(),
		"metric",
		fmt.Sprintf("%d", priority+1),
		"if",
		fmt.Sprintf("%d", ifIndex),
	}
	v, err := exec.Command("route.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to add %s route to %s interface: %s: %s: %s", dst, name, args, v, err)
	}
	return nil
}

func RouteDel(dst interface{}, gw net.IP, priority int, name string) error {
	d := util.GetNet(dst)
	args := []string{
		"delete",
		d.IP.String(),
		"mask",
		net.IP(d.Mask).To4().String(),
		gw.String(),
		"metric",
		fmt.Sprintf("%d", priority+1),
		"if",
		fmt.Sprintf("%d", ifIndex),
	}
	v, err := exec.Command("route.exe", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete %s route from %s interface: %s: %s: %s", dst, name, args, v, err)
	}
	return nil
}
