package tun

import (
	"fmt"
	"net"

	"github.com/kayrus/tuncfg/log"
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

	defer func() {
		if err != nil {
			// destroy interface on error
			e := tunDev.Close()
			if e != nil {
				log.Errorf("error closing interface: %v", e)
			}
		}
	}()

	nativeTun, ok := tunDev.(*tun.NativeTun)
	if !ok {
		err = fmt.Errorf("failed to assert tun.NativeTun")
		return nil, err
	}

	err = setInterface(nativeTun, local, gw, mtu)
	if err != nil {
		return nil, fmt.Errorf("failed to configure interface: %v", err)
	}

	return nativeTun, nil
}
