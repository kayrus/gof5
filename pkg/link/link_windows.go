// +build windows

package link

import (
	"golang.zx2c4.com/wireguard/tun"
)

type f5Tun struct {
	tun.Device
	f5Conn
}

func (t *f5Tun) Read(b []byte) (int, error) {
	if t.Device != nil {
		return t.Device.Read(b, 0)
	}
	return t.f5Conn.Read(b)
}

func (t *f5Tun) Write(b []byte) (int, error) {
	if t.Device != nil {
		return t.Device.Write(b, 0)
	}
	return t.f5Conn.Write(b)
}

func (t *f5Tun) Close() error {
	if t.Device != nil {
		return t.Device.Close()
	}
	return t.f5Conn.Close()
}
