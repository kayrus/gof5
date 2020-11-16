package pkg

import (
	"net"
)

func getNet(v interface{}) *net.IPNet {
	if v == nil {
		return nil
	}

	switch v := v.(type) {
	case net.IP:
		if v == nil {
			return nil
		}

		if v := v.To4(); v != nil {
			return &net.IPNet{IP: v, Mask: net.CIDRMask(net.IPv4len*8, net.IPv4len*8)}
		}
		if v := v.To16(); v != nil {
			return &net.IPNet{IP: v, Mask: net.CIDRMask(net.IPv6len*8, net.IPv6len*8)}
		}
	case *net.IPNet:
		if v == nil || v.IP == nil || v.Mask == nil {
			return nil
		}

		if ip := v.IP.To4(); ip != nil {
			if _, bits := v.Mask.Size(); bits == net.IPv4len*8 {
				return &net.IPNet{IP: ip, Mask: v.Mask}
			}
		}
		if ip := v.IP.To16(); ip != nil {
			if _, bits := v.Mask.Size(); bits == net.IPv6len*8 {
				return &net.IPNet{IP: ip, Mask: v.Mask}
			}
		}
	}

	return nil
}
