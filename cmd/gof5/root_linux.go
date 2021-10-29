//go:build linux
// +build linux

package main

import (
	"fmt"
	"os"
	"strings"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

func checkCapability(c *cap.Set, capability cap.Value) error {
	// when "setcap capability+ep gof5" was used
	capable, err := c.GetFlag(cap.Effective, capability)
	if err != nil {
		return fmt.Errorf("failed to get process effective capability flag: %v", err)
	}
	if capable {
		return nil
	}

	// when "setcap capability+p gof5" or "setcap capability+i gof5" was used and a user has inheritable capability
	capable, err = c.GetFlag(cap.Permitted, capability)
	if err != nil {
		return fmt.Errorf("failed to get process permitted capability flag: %v", err)
	}
	if capable {
		if err = c.SetFlag(cap.Effective, true, capability); err != nil {
			return fmt.Errorf("permitted capability detected: failed to set effective %s capability flag: %v", strings.ToUpper(capability.String()), err)
		}
		if err = c.SetProc(); err != nil {
			return fmt.Errorf("permitted capability detected: failed to set effective %s capability: %v", strings.ToUpper(capability.String()), err)
		}
		return nil
	}

	return fmt.Errorf("cannot obtain effective %s capability", strings.ToUpper(capability.String()))
}

// TODO: detect cap_net_bind_service for DNS bind
func checkPermissions() error {
	// check root first
	if uid := os.Getuid(); uid == 0 {
		return nil
	}

	c := cap.GetProc()

	var err error
	capabilities := []cap.Value{
		cap.NET_ADMIN, // to create and manage tun interface
		// no need to run own DNS proxy, when systemd-resolved is used
		// cap.NET_BIND_SERVICE, // to bind DNS proxy
	}
	for _, capability := range capabilities {
		err = checkCapability(c, capability)
		if err != nil {
			break
		}
	}

	if err == nil {
		return nil
	}

	// no capabilities or "setcap capability+i gof5" was used and a user has no inheritable capability
	return fmt.Errorf("gof5 needs to run with CAP_NET_ADMIN capability or as root: %v", err)
}
