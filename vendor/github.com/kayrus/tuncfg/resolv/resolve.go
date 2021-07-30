// +build linux

package resolv

import (
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/kayrus/tuncfg/log"

	"github.com/godbus/dbus/v5"
	"golang.org/x/sys/unix"
)

const (
	// systemd-resolved constants
	resolveInterface      = "org.freedesktop.resolve1"
	resolveObjectPath     = "/org/freedesktop/resolve1"
	resolveGetLink        = resolveInterface + ".Manager.GetLink"
	resolveSetLinkDNS     = resolveInterface + ".Manager.SetLinkDNS"
	resolveSetLinkDomains = resolveInterface + ".Manager.SetLinkDomains"
	resolveRevertLink     = resolveInterface + ".Manager.RevertLink"
	resolveGetDNSProperty = resolveInterface + ".Link.DNS"
)

var resolveListenAddr = net.IPv4(127, 0, 0, 53)

type resolveLinkDns struct {
	Family  int32
	Address []byte
}

type resolveLinkDomain struct {
	Domain      string
	RoutingOnly bool
}

func (h *Handler) isResolve() bool {
	if len(h.nmViaResolved) > 0 {
		return false
	}

	// detect default DNS server from resolved, when networkManager is also used
	conn, err := newDbusConn()
	if err != nil {
		return false
	}
	defer conn.Close()

	// get all interfaces
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	obj := conn.Object(resolveInterface, resolveObjectPath)
	ifaceDNS := make(map[int][]net.IP)
	for _, iface := range ifaces {
		var devPath dbus.ObjectPath
		err = obj.Call(resolveGetLink, 0, iface.Index).Store(&devPath)
		if err != nil {
			return false
		}

		dev := conn.Object(resolveInterface, devPath)
		v, err := dev.GetProperty(resolveGetDNSProperty)
		if err != nil {
			return false
		}
		if v, ok := v.Value().([][]interface{}); ok {
			for _, v := range v {
				if v, ok := v[0].(int32); !ok {
					continue
				} else if v != unix.AF_INET {
					continue
				}
				if len(v) > 1 {
					if v, ok := v[1].([]byte); ok && net.IP(v).To4() != nil {
						ifaceDNS[iface.Index] = append(ifaceDNS[iface.Index], v)
					}
				}
			}
		}
	}

	// interfaces with DNS found, pick the last one
	if l := len(ifaceDNS); l > 0 {
		keys := make([]int, 0, len(ifaceDNS))
		for k := range ifaceDNS {
			keys = append(keys, k)
		}
		sort.Ints(keys)

		h.nmViaResolved = ifaceDNS
		// override h.origDnsServers
		h.origDnsServers = ifaceDNS[keys[l-1]]
	}

	for _, ip := range h.origDnsServers {
		if ip.Equal(resolveListenAddr) {
			return true
		}
	}

	return false
}

func (h *Handler) setResolve() error {
	log.Debugf("Configuring systemd-resolved")

	conn, err := newDbusConn()
	if err != nil {
		return err
	}
	defer conn.Close()

	obj := conn.Object(resolveInterface, resolveObjectPath)
	linkDns := make([]resolveLinkDns, len(h.dnsServers))
	for i, s := range h.dnsServers {
		if v := s.To4(); v != nil {
			linkDns[i] = resolveLinkDns{
				Family:  unix.AF_INET,
				Address: v,
			}
		} else {
			linkDns[i] = resolveLinkDns{
				Family:  unix.AF_INET6,
				Address: s,
			}
		}
	}
	err = obj.Call(resolveSetLinkDNS, 0, h.iface.Index, linkDns).Store()
	if err != nil {
		return fmt.Errorf("failed to set %q DNS servers: %v", h.dnsServers, err)
	}

	var index int
	linkDomains := make([]resolveLinkDomain, len(h.dnsSuffixes)+len(h.dnsDomains))
	for i, d := range h.dnsDomains {
		// don't trim global settings
		if d != "." {
			d = strings.TrimLeft(d, ".")
		}
		linkDomains[i] = resolveLinkDomain{
			Domain:      d,
			RoutingOnly: true,
		}
		index = i + 1
	}
	for i, d := range h.dnsSuffixes {
		linkDomains[i+index] = resolveLinkDomain{
			Domain: d,
		}
	}
	err = obj.Call(resolveSetLinkDomains, 0, h.iface.Index, linkDomains).Store()
	if err != nil {
		return fmt.Errorf("failed to set search and routing domains: %+v: %v", linkDomains, err)
	}

	return nil
}

func (h *Handler) restoreResolve() {
	conn, err := newDbusConn()
	if err != nil {
		log.Errorf("%v", err)
		return
	}
	defer conn.Close()

	obj := conn.Object(resolveInterface, resolveObjectPath)

	// TODO: fix wireguard VPN DNS not being restored
	err = obj.Call(resolveRevertLink, 0, h.iface.Index).Store()
	if err != nil {
		log.Errorf("%v", err)
		return
	}

	return
}
