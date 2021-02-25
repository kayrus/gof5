// +build !windows

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
		// unix.IFF_NO_PI is not set, therefore we receive packet information
		n, err := t.Device.File().Read(b)
		if n < 4 {
			return 0, err
		}
		// shift slice to the left
		return copy(b[:n-4], b[4:n]), nil
	}
	return t.f5Conn.Read(b)
}

func (t *f5Tun) Write(b []byte) (int, error) {
	if t.Device != nil {
		return t.Device.Write(append(make([]byte, 4), b...), 4)
	}
	return t.f5Conn.Write(b)
}

func (t *f5Tun) Close() error {
	if t.Device != nil {
		return t.Device.Close()
	}
	return t.f5Conn.Close()
}
