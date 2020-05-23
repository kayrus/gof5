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
	if gw == nil {
		link, err := netlink.LinkByName(iface)
		if err != nil {
			return fmt.Errorf("failed to get %q interface by name: %s", iface, err)
		}
		route.LinkIndex = link.Attrs().Index
	}
	if err := netlink.RouteAdd(&route); err != nil {
		return fmt.Errorf("failed to add %s route to %q interface: %s", dst, iface, err)
	}
	return nil
}

func routeDel(dst interface{}, gw net.IP, priority int, iface string) error {
	route := netlink.Route{
		Dst:      getNet(dst),
		Priority: priority,
		Gw:       gw,
	}
	if gw == nil {
		link, err := netlink.LinkByName(iface)
		if err != nil {
			return fmt.Errorf("failed to get %q interface by name: %s", iface, err)
		}
		route.LinkIndex = link.Attrs().Index
	}
	if err := netlink.RouteDel(&route); err != nil {
		return fmt.Errorf("failed to delete %s route from %q interface: %s", dst, iface, err)
	}
	return nil
}
