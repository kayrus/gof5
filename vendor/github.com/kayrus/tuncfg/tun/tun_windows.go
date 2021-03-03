package tun

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

const Offset = 0

func (t *Tunnel) Read(b []byte) (int, error) {
	return t.NativeTun.Read(b, Offset)
}

func (t *Tunnel) Write(b []byte) (int, error) {
	return t.NativeTun.Write(b, Offset)
}

func (t *Tunnel) Close() error {
	return t.NativeTun.Close()
}

func setInterface(tun *tun.NativeTun, local, gw *net.IPNet) error {
	name, err := tun.Name()
	if err != nil {
		return err
	}

	luid := winipcfg.LUID(tun.LUID())

	err = luid.SetIPAddresses([]net.IPNet{*local})
	if err != nil {
		return fmt.Errorf("failed to set local IP on %s interface: %s", name, err)
	}

	return nil
}
