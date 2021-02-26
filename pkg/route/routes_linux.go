// +build linux

package route

import (
	"fmt"
	"net"

	"github.com/kayrus/gof5/pkg/util"

	"github.com/vishvananda/netlink"
)

var link netlink.Link

func SetInterface(name string, local, server net.IP, mtu int) error {
	var err error
	link, err = netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to detect %s interface: %s", name, err)
	}
	err = netlink.LinkSetMTU(link, mtu)
	if err != nil {
		return fmt.Errorf("failed to set MTU on %s interface: %s", name, err)
	}
	/*
	   err = netlink.LinkSetARPOn(link)
	   if err != nil {
	           return fmt.Errorf("failed to set ARP on %s interface: %s", name, err)
	   }
	   err = netlink.LinkSetAllmulticastOff(link)
	   if err != nil {
	           return fmt.Errorf("failed to set multicast on %s interface: %s", name, err)
	   }
	*/
	ipv4Addr := &netlink.Addr{
		IPNet: util.GetNet(local),
		Peer:  util.GetNet(server),
	}
	err = netlink.AddrAdd(link, ipv4Addr)
	if err != nil {
		return fmt.Errorf("failed to set peer address on %s interface: %s", name, err)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("failed to set %s interface up: %s", name, err)
	}
	return nil
}

func RouteAdd(dst interface{}, gw net.IP, priority int, name string) error {
	route := netlink.Route{
		Dst:      util.GetNet(dst),
		Priority: priority,
		Gw:       gw,
	}
	if gw == nil {
		if link == nil {
			var err error
			link, err = netlink.LinkByName(name)
			if err != nil {
				return fmt.Errorf("failed to detect %s interface: %s", name, err)
			}
		}
		route.LinkIndex = link.Attrs().Index
	}
	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf("failed to add %s route to %q interface: %s", dst, name, err)
	}
	return nil
}

func RouteDel(dst interface{}, gw net.IP, priority int, name string) error {
	route := netlink.Route{
		Dst:      util.GetNet(dst),
		Priority: priority,
		Gw:       gw,
	}
	if gw == nil {
		if link == nil {
			var err error
			link, err = netlink.LinkByName(name)
			if err != nil {
				return fmt.Errorf("failed to detect %s interface: %s", name, err)
			}
		}
		route.LinkIndex = link.Attrs().Index
	}
	if err := netlink.RouteDel(&route); err != nil {
		return fmt.Errorf("failed to delete %s route from %q interface: %s", dst, name, err)
	}
	return nil
}
