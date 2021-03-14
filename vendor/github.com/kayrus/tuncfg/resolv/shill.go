// +build linux

package resolv

import (
	"fmt"
	"net"

	"github.com/kayrus/tuncfg/log"

	"github.com/godbus/dbus/v5"
)

const (
	// shill constants
	// https://chromium.googlesource.com/chromiumos/platform/flimflam/+/refs/heads/main/doc/ipconfig-api.txt
	shillInterface            = "org.chromium.flimflam"
	shillManagerGetProperties = shillInterface + ".Manager.GetProperties"
	shillServiceSetProperty   = shillInterface + ".Service.SetProperty"
	shillServiceClearProperty = shillInterface + ".Service.ClearProperty"
)

func (h *Handler) isShill() bool {
	if h.dbusShillServicePath != "" {
		return true
	}

	conn, err := newDbusConn()
	if err != nil {
		return false
	}
	defer conn.Close()

	obj := conn.Object(shillInterface, "/")

	props := make(map[string]dbus.Variant)
	err = obj.Call(shillManagerGetProperties, 0).Store(&props)
	if err != nil {
		return false
	}

	if v, ok := props["DefaultService"]; ok && v.Value() != "" {
		path, ok := v.Value().(dbus.ObjectPath)
		if !ok {
			return false
		}
		h.dbusShillServicePath = string(path)
		return true
	}

	return false
}

func updateShill(conn *dbus.Conn, dbusPath string, dnsServers []net.IP, dnsSuffixes []string) error {
	obj := conn.Object(shillInterface, dbus.ObjectPath(dbusPath))

	linkDns := make([]string, len(dnsServers))
	for i, s := range dnsServers {
		linkDns[i] = s.String()
	}
	if dnsServers != nil {
		props := map[string]interface{}{
			"NameServers":   linkDns,
			"SearchDomains": dnsSuffixes,
		}
		err := obj.Call(shillServiceSetProperty, 0, "StaticIPConfig", props).Store()
		if err != nil {
			return fmt.Errorf("failed to set %q DNS servers: %v", dnsServers, err)
		}
		return nil
	}

	// restore original DNS suffixes
	props := map[string]interface{}{
		"SearchDomains": dnsSuffixes,
	}
	err := obj.Call(shillServiceSetProperty, 0, "StaticIPConfig", props).Store()
	if err != nil {
		return fmt.Errorf("failed to set %q DNS suffixes: %v", dnsSuffixes, err)
	}

	/*
		// for some reason this call doesn't restore original search domains
		// clear StaticIPConfig
		err = rs.set(shillServiceClearProperty, "StaticIPConfig")
		if err != nil {
			return fmt.Errorf("failed to set %q DNS suffixes: %v", dnsSuffixes, err)
		}
	*/

	return nil
}

func (h *Handler) setShill() error {
	log.Debugf("Configuring CromeOS shill")

	conn, err := newDbusConn()
	if err != nil {
		return err
	}
	defer conn.Close()

	return updateShill(conn, h.dbusShillServicePath, h.dnsServers, h.dnsSuffixes)
}

func (h *Handler) restoreShill() {
	conn, err := newDbusConn()
	if err != nil {
		log.Errorf("%v", err)
		return
	}
	defer conn.Close()

	err = updateShill(conn, h.dbusShillServicePath, nil, h.origDnsSuffixes)
	if err != nil {
		log.Errorf("%v", err)
		return
	}
	return
}
