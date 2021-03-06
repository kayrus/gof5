// +build darwin freebsd

package route

import (
	"fmt"
	"net"
	"syscall"

	"github.com/kayrus/tuncfg/log"
	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
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

	_, err = unix.Write(socket, bin[:])
	return err
}

func (h *Handler) Add() {
	socket, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		log.Errorf("could not create route socket: %v", err)
		return
	}

	for _, cidr := range h.routes {
		if err := h.processRoute(socket, cidr, syscall.RTM_ADD); err != nil {
			log.Errorf("failed to add %s route: %v", cidr, err)
		}
	}

	unix.Shutdown(socket, unix.SHUT_RDWR)
	err = unix.Close(socket)
	if err != nil {
		log.Errorf("cannot close route socket: %v", err)
	}
}

func (h *Handler) Del() {
	socket, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		log.Errorf("could not create route socket: %v", err)
		return
	}

	for _, cidr := range h.routes {
		if err := h.processRoute(socket, cidr, syscall.RTM_DELETE); err != nil {
			log.Errorf("failed to delete %s route: %v", cidr, err)
		}
	}

	unix.Shutdown(socket, unix.SHUT_RDWR)
	err = unix.Close(socket)
	if err != nil {
		log.Errorf("cannot close route socket: %v", err)
	}
}
