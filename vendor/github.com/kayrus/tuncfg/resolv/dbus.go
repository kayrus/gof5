// +build linux

package resolv

import (
	"fmt"

	"github.com/godbus/dbus/v5"
)

func newDbusConn() (*dbus.Conn, error) {
	conn, err := dbus.SystemBusPrivate()
	if err != nil {
		return nil, fmt.Errorf("cannot connect to dbus: %v", err)
	}
	if err = conn.Auth(nil); err != nil {
		conn.Close()
		conn = nil
		return nil, fmt.Errorf("cannot auth against dbus: %v", err)
	}
	if err = conn.Hello(); err != nil {
		conn.Close()
		conn = nil
		return nil, fmt.Errorf("cannot establish a connection with dbus: %v", err)
	}

	return conn, nil
}
