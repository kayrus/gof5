package tun

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/tun"
)

// A wrapper for a proper Reader and Writer
type Tunnel struct {
	*tun.NativeTun
}

func OpenTunDevice(local, gw *net.IPNet, name string, mtu int) (*tun.NativeTun, error) {
	tunDev, err := tun.CreateTUN(name, mtu)
	if err != nil {
		return nil, err
	}

	nativeTun, ok := tunDev.(*tun.NativeTun)
	if !ok {
		return nil, fmt.Errorf("failed to assert tun.NativeTun")
	}

	err = setInterface(nativeTun, local, gw)
	if err != nil {
		return nil, fmt.Errorf("failed to configure interface: %v", err)
	}

	return nativeTun, nil
}
