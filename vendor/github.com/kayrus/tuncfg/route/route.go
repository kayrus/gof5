package route

import (
	"fmt"
	"net"
	"strings"

	"github.com/IBM/netaddr"
	"github.com/kayrus/tuncfg/log"
)

func New(name string, routes []*net.IPNet, gw net.IP, priority int) (*Handler, error) {
	return newHandler(name, routes, gw, priority)
}

func splitFunc(c rune) bool {
	return c == ',' || c == ' '
}

func getNet(ip net.IP) *net.IPNet {
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}
}

func Build(local, gw *net.IPNet, routes, excludeRoutes string) ([]*net.IPNet, error) {
	res := &netaddr.IPSet{}
	res.RemoveNet(local)
	res.RemoveNet(gw)

	for _, cidr := range strings.FieldsFunc(routes, splitFunc) {
		if v := net.ParseIP(cidr).To4(); v != nil {
			res.InsertNet(getNet(v))
			log.Debugf("including %s to routes", v)
			continue
		}

		_, v, err := net.ParseCIDR(cidr)
		if err != nil {
			// trying to lookup a hostname
			if ips, err := net.LookupIP(cidr); err == nil {
				for _, v := range ips {
					if v := v.To4(); v != nil {
						log.Debugf("including %s (%s) to routes", cidr, v)
						res.InsertNet(getNet(v))
					}
				}
				continue
			} else {
				return nil, fmt.Errorf("failed to resolve %q: %v", cidr, err)
			}
			return nil, fmt.Errorf("failed to parse %s CIDR: %v", cidr, err)
		}
		log.Debugf("including %s to routes", v)
		res.InsertNet(v)
	}

	for _, cidr := range strings.FieldsFunc(excludeRoutes, splitFunc) {
		if v := net.ParseIP(cidr).To4(); v != nil {
			res.RemoveNet(getNet(v))
			log.Debugf("excluding %s from routes", v)
			continue
		}

		_, v, err := net.ParseCIDR(cidr)
		if err != nil {
			// trying to lookup a hostname
			if ips, err := net.LookupIP(cidr); err == nil {
				for _, v := range ips {
					if v := v.To4(); v != nil {
						log.Debugf("excluding %s (%s) from routes", cidr, v)
						res.RemoveNet(getNet(v))
					}
				}
				continue
			} else {
				return nil, fmt.Errorf("failed to resolve %q: %v", cidr, err)
			}
			return nil, fmt.Errorf("failed to parse %s CIDR: %v", cidr, err)
		}
		log.Debugf("excluding %s from routes", v)
		res.RemoveNet(v)
	}

	return res.GetNetworks(), nil
}
