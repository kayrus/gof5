package route

import (
	"fmt"
	"net"

	"github.com/vishvananda/netlink"
)

func (h *Handler) routeAdd(dst *net.IPNet) error {
	route := netlink.Route{
		Dst:      dst,
		Priority: h.priority,
		Gw:       h.gw,
	}
	if h.gw == nil {
		route.LinkIndex = h.iface.Index
	}
	if err := netlink.RouteReplace(&route); err != nil {
		return fmt.Errorf("failed to add %s route to %q interface: %s", dst, h.iface.Name, err)
	}
	return nil
}

func (h *Handler) routeDel(dst *net.IPNet) error {
	route := netlink.Route{
		Dst:      dst,
		Priority: h.priority,
		Gw:       h.gw,
	}
	if h.gw == nil {
		route.LinkIndex = h.iface.Index
	}
	if err := netlink.RouteDel(&route); err != nil {
		return fmt.Errorf("failed to delete %s route from %q interface: %s", dst, h.iface.Name, err)
	}
	return nil
}
