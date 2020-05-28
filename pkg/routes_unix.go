// +build !linux

package pkg

import (
	"fmt"
	"net"
	"os/exec"

	"github.com/jackpal/gateway"
)

/*
func setDNS(l *vpnLink( error {
        v, err := exec.Command("networksetup", "-setdnsservers" "Wi-Fi", l.).Output()
        if err != nil {
                return fmt.Errorf("failed to set MTU: %s: %s", v, err)
        }
}
*/

func setInterface(l *vpnLink) error {
	v, err := exec.Command("ifconfig", l.name, "mtu", fmt.Sprintf("%d", l.mtuInt)).Output()
	if err != nil {
		return fmt.Errorf("failed to set MTU: %s: %s", v, err)
	}
	v, err = exec.Command("ifconfig", l.name, "inet", getNet(l.localIPv4).String(), l.serverIPv4.String()).Output()
	if err != nil {
		return fmt.Errorf("failed to set ip addr: %s: %s", v, err)
	}
	v, err = exec.Command("ifconfig", l.name, "up").Output()
	if err != nil {
		return fmt.Errorf("failed to bring up interface: %s: %s", v, err)
	}
	return nil
}

func routeGet(dst net.IP) ([]net.IP, error) {
	v, err := gateway.DiscoverGateway()
	if err != nil {
		return nil, fmt.Errorf("failed to discover the gateway for %s: %s", dst, err)
	}
	return []net.IP{v}, nil
}

func routeAdd(dst interface{}, gw net.IP, priority int, iface string) error {
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
		"delete",
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
