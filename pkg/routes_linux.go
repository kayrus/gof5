// +build linux

package pkg

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func setInterface(l *vpnLink) error {
	var err error
	l.link, err = netlink.LinkByName(l.name)
	if err != nil {
		return fmt.Errorf("failed to detect %s interface: %s", l.name, err)
	}
	err = netlink.LinkSetMTU(l.link, int(l.mtuInt))
	if err != nil {
		return fmt.Errorf("failed to set MTU on %s interface: %s", l.name, err)
	}
	/*
		err = netlink.LinkSetARPOn(l.link)
		if err != nil {
			l.errChan <- fmt.Errorf("failed to set ARP on %s interface: %s", l.name, err)
			return
		}
		err = netlink.LinkSetAllmulticastOff(l.link)
		if err != nil {
			l.errChan <- fmt.Errorf("failed to set multicast on %s interface: %s", l.name, err)
			return
		}
	*/
	ipv4Addr := &netlink.Addr{
		IPNet: getNet(l.localIPv4),
		Peer:  getNet(l.serverIPv4),
	}
	err = netlink.AddrAdd(l.link, ipv4Addr)
	if err != nil {
		return fmt.Errorf("failed to set peer address on %s interface: %s", l.name, err)
	}
	err = netlink.LinkSetUp(l.link)
	if err != nil {
		return fmt.Errorf("failed to set %s interface up: %s", l.name, err)
	}
	return nil
}

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
	if err := netlink.RouteReplace(&route); err != nil {
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
