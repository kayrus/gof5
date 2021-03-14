// +build linux

package resolv

import (
	"fmt"
	"net"
	"strings"

	"github.com/kayrus/tuncfg/log"

	"golang.org/x/sys/unix"
)

const (
	// systemd-resolved constants
	resolveInterface      = "org.freedesktop.resolve1"
	resolveObjectPath     = "/org/freedesktop/resolve1"
	resolveSetLinkDNS     = resolveInterface + ".Manager.SetLinkDNS"
	resolveSetLinkDomains = resolveInterface + ".Manager.SetLinkDomains"
	resolveRevertLink     = resolveInterface + ".Manager.RevertLink"
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

	err = obj.Call(resolveRevertLink, 0, h.iface.Index).Store()
	if err != nil {
		log.Errorf("%v", err)
		return
	}

	return
}
