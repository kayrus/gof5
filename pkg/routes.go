package pkg

import (
	"net"
)

func getNet(v interface{}) *net.IPNet {
	switch v := v.(type) {
	case net.IP:
		return &net.IPNet{IP: v, Mask: net.CIDRMask(32, 32)}
	case *net.IPNet:
		return v
	}
	return nil
}
