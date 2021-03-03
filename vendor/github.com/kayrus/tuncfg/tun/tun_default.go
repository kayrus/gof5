// +build !windows

package tun

import (
	"fmt"
)

const Offset = 4

func (t *Tunnel) Read(b []byte) (int, error) {
	// unix.IFF_NO_PI is not set, therefore we receive packet information
	n, err := t.NativeTun.Read(b, Offset)
	if err != nil {
		return n, err
	}
	if l := len(b); l < n+Offset {
		return n, fmt.Errorf("wrong size: %d < %d", l, n+Offset)
	}
	// cut off Offset bytes
	return copy(b[:n], b[Offset:n+Offset]), nil
}

func (t *Tunnel) Write(b []byte) (int, error) {
	// unix.IFF_NO_PI is not set, therefore we need to send data with the Offset
	return t.NativeTun.Write(append(make([]byte, Offset, len(b)+Offset), b...), Offset)
}

func (t *Tunnel) Close() error {
	return t.NativeTun.Close()
}
