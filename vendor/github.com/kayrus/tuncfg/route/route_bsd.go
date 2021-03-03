// +build darwin freebsd

package route

import (
	"fmt"
	"net"
	"syscall"

	"github.com/kayrus/tuncfg/log"
	"golang.org/x/net/route"
)

func (h *Handler) processRoute(socket int, dest *net.IPNet, action uint8) error {
	var addr, mask, hop route.Addr

	a := &route.Inet4Addr{}
	m := &route.Inet4Addr{}
	addr = a
	mask = m
	copy(a.IP[:], dest.IP.To4())
	copy(m.IP[:], net.IP(dest.Mask).To4())

	if h.gw != nil {
		v := &route.Inet4Addr{}
		hop = v
		copy(v.IP[:], h.gw.To4())
	} else if h.iface != nil {
		hop = &route.LinkAddr{
			Index: h.iface.Index,
			Name:  h.iface.Name,
			Addr:  h.iface.HardwareAddr,
		}
	} else {
		return fmt.Errorf("gateway is not specified")
	}

	msg := route.RouteMessage{
		Version: syscall.RTM_VERSION,
		Type:    int(action),
		Index:   0,
		Flags:   (syscall.RTF_UP | syscall.RTF_GATEWAY | syscall.RTF_PINNED),
		Seq:     1,
		Addrs: []route.Addr{
			addr,
			hop,
			mask,
		},
	}
	bin, err := msg.Marshal()
	if err != nil {
		return err
	}

	_, err = syscall.Write(socket, bin[:])
	return err
}

func (h *Handler) Add() {
	socket, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		log.Debugf("could not create route socket: %v", err)
		return
	}

	for _, cidr := range h.routes {
		if err := h.processRoute(socket, cidr, syscall.RTM_ADD); err != nil {
			log.Debugf("failed to add route: %v", err)
		}
	}
}

func (h *Handler) Del() {
	socket, err := syscall.Socket(syscall.AF_ROUTE, syscall.SOCK_RAW, syscall.AF_UNSPEC)
	if err != nil {
		log.Debugf("could not create route socket: %v", err)
		return
	}

	for _, cidr := range h.routes {
		if err := h.processRoute(socket, cidr, syscall.RTM_DELETE); err != nil {
			log.Debugf("failed to delete route: %v", err)
		}
	}
}
