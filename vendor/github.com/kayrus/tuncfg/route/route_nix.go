// +build !windows

package route

import (
	"net"
)

type Handler struct {
	iface    *net.Interface
	index    int
	routes   []*net.IPNet
	gw       net.IP
	priority int
}

func newHandler(name string, routes []*net.IPNet, gw net.IP, priority int) (*Handler, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}

	return &Handler{
		iface:    ifc,
		routes:   routes,
		gw:       gw,
		priority: priority,
	}, nil
}
