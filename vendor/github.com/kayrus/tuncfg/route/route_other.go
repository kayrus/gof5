// +build linux windows

package route

import (
	"github.com/kayrus/tuncfg/log"
)

func (h *Handler) Add() {
	for _, cidr := range h.routes {
		if err := h.routeAdd(cidr); err != nil {
			log.Errorf("failed to add %s route: %v", cidr, err)
		}
	}
}

func (h *Handler) Del() {
	for _, cidr := range h.routes {
		if err := h.routeDel(cidr); err != nil {
			log.Errorf("failed to delete %s route: %v", cidr, err)
		}
	}
}
