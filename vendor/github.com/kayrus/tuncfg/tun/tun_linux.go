package tun

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

func setInterface(tun *tun.NativeTun, local, gw *net.IPNet, _ int) error {
	name, err := tun.Name()
	if err != nil {
		return err
	}

	link, err := netlink.LinkByName(name)
	if err != nil {
		return fmt.Errorf("failed to detect %s interface: %s", name, err)
	}

	ipv4Addr := &netlink.Addr{
		IPNet: local,
		Peer:  gw,
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
