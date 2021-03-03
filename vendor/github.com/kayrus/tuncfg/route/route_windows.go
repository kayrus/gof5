package route

import (
	"fmt"
	"net"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

type Handler struct {
	name     string
	luid     winipcfg.LUID
	routes   []*net.IPNet
	gw       net.IP
	priority uint32
}

func newHandler(name string, routes []*net.IPNet, gw net.IP, priority int) (*Handler, error) {
	ifc, err := net.InterfaceByName(name)
	if err != nil {
		return nil, err
	}

	luid, err := winipcfg.LUIDFromIndex(uint32(ifc.Index))
	if err != nil {
		return nil, err
	}

	return &Handler{
		name:     name,
		luid:     luid,
		routes:   routes,
		gw:       gw,
		priority: uint32(priority) + 1,
	}, nil
}

func (h *Handler) routeAdd(dst *net.IPNet) error {
	err := h.luid.AddRoute(*dst, h.gw, h.priority)
	if err != nil {
		return fmt.Errorf("failed to add %s route to %s interface: %s", dst, h.name, err)
	}
	return nil
}

func (h *Handler) routeDel(_ *net.IPNet) error {
	err := h.luid.FlushRoutes(windows.AF_UNSPEC)
	if err != nil {
		return fmt.Errorf("failed to flush routes on %s interface: %s", h.name, err)
	}

	return nil
}
