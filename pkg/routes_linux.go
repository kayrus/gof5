// +build linux

package pkg

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func routeGet(dst net.IP) ([]net.IP, error) {
	v, err := netlink.RouteGet(dst)
	if err != nil {
		return nil, fmt.Errorf("failed to discover the gateway for %s: %s", dst, err)
	}
	gateways := make([]net.IP, len(v))
	for i, v := range v {
		gateways[i] = v.Gw
	}
	return gateways, nil
}

func routeAdd(dst interface{}, gw net.IP, priority int, iface string) error {
	route := netlink.Route{
		Dst:      getNet(dst),
		Priority: priority,
		Gw:       gw,
	}
	if err := netlink.RouteAdd(&route); err != nil {
		return fmt.Errorf("failed to add %s route to %s interface: %s", dst, iface, err)
	}
	return nil
}

func routeDel(dst interface{}, gw net.IP, priority int, iface string) error {
	route := netlink.Route{
		Dst:      getNet(dst),
		Priority: priority,
		Gw:       gw,
	}
	if err := netlink.RouteDel(&route); err != nil {
		return fmt.Errorf("failed to delete %s route from %s interface: %s", dst, iface, err)
	}
	return nil
}
