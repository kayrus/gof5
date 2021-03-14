// +build linux

package resolv

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/kayrus/tuncfg/log"

	"github.com/godbus/dbus/v5"
)

const (
	// NetworkManager constants
	nmInterface                  = "org.freedesktop.NetworkManager"
	nmObjectPath                 = "/org/freedesktop/NetworkManager"
	nmDnsManagerPath             = "/org/freedesktop/NetworkManager/DnsManager"
	nmGetDevices                 = nmInterface + ".GetDevices"
	nmGetDeviceActiveConnection  = nmInterface + ".Device.ActiveConnection"
	nmGetActiveConnectionDefault = nmInterface + ".Connection.Active.Default"
	nmDeviceGetAppliedConnection = nmInterface + ".Device.GetAppliedConnection"
	nmDeviceReapply              = nmInterface + ".Device.Reapply"
	nmDnsManagerConfiguration    = nmInterface + ".DnsManager.Configuration"
)

func (h *Handler) isNetworkManager() bool {
	if h.dbusNmConnectionPath != "" {
		return true
	}

	conn, err := newDbusConn()
	if err != nil {
		return false
	}
	defer conn.Close()

	// list current devices
	var devices []dbus.ObjectPath
	obj := conn.Object(nmInterface, nmObjectPath)
	err = obj.Call(nmGetDevices, 0).Store(&devices)
	if err != nil {
		return false
	}

	// detect the default active connection to modify DNS settings on
	// if we apply DNS settings on tun interface, they won't be reflected in /etc/resolv.conf
	for _, devPath := range devices {
		dev := conn.Object(nmInterface, devPath)
		v, err := dev.GetProperty(nmGetDeviceActiveConnection)
		if err != nil {
			return false
		}
		path, ok := v.Value().(dbus.ObjectPath)
		if !ok || path == "/" {
			continue
		}
		dev = conn.Object(nmInterface, path)
		v, err = dev.GetProperty(nmGetActiveConnectionDefault)
		if err != nil {
			return false
		}
		if def, ok := v.Value().(bool); ok && def {
			h.dbusNmConnectionPath = string(devPath)
			return true
		}
	}

	return false
}

func updateNetworkManager(conn *dbus.Conn, dbusPath string, dnsServers []net.IP, dnsSuffixes []string) error {
	obj := conn.Object(nmInterface, dbus.ObjectPath(dbusPath))

	opts := make(map[string]map[string]dbus.Variant)
	var version uint64

	err := obj.Call(nmDeviceGetAppliedConnection, 0, uint(0)).Store(&opts, &version)
	if err != nil {
		return fmt.Errorf("failed to get current connection options: %v", err)
	}

	ipv4, ok := opts["ipv4"]
	if !ok {
		return fmt.Errorf("failed to detect IPv4 config")
	}

	var linkDns []uint32
	for _, s := range dnsServers {
		if v := s.To4(); v != nil {
			// TODO: other architectures have different endian?
			linkDns = append(linkDns, binary.LittleEndian.Uint32(v))
		}
	}

	// update DNS settings
	ipv4["dns"] = dbus.MakeVariant(linkDns)
	ipv4["dns-search"] = dbus.MakeVariant(dnsSuffixes)
	ipv4["dns-priority"] = dbus.MakeVariant(-1)

	removeKeys := []string{
		"addresses", "routes",
	}
	for _, property := range removeKeys {
		delete(opts["ipv4"], property)
		delete(opts["ipv6"], property)
	}
	//fmt.Printf("New Options %d: %+#v\n", version, opts)

	// TODO: simple update, e.g. Update2
	err = obj.Call(nmDeviceReapply, 0, opts, version, uint(0)).Store()
	if err != nil {
		return fmt.Errorf("failed to set search domains: %+v: %v", dnsSuffixes, err)
	}
	return nil
}

func (h *Handler) detectRealDNS(conn *dbus.Conn) error {
	obj := conn.Object(nmInterface, nmDnsManagerPath)
	v, err := obj.GetProperty(nmDnsManagerConfiguration)
	if err != nil {
		return err
	}

	if v, ok := v.Value().([]map[string]dbus.Variant); ok {
		for _, v := range v {
			if v, ok := v["nameservers"]; ok {
				if v, ok := v.Value().([]string); ok {
					// overwrite DNS detected from /etc/resolv.conf
					h.origDnsServers = []net.IP{}
					for _, v := range v {
						if v := net.ParseIP(v); v != nil {
							h.origDnsServers = append(h.origDnsServers, v)
						}
					}
					return nil
				}
			}
		}
	}

	return nil
}

func (h *Handler) setNetworkManager() error {
	log.Debugf("Configuring NetworkManager")

	conn, err := newDbusConn()
	if err != nil {
		return err
	}
	defer conn.Close()

	if h.isResolve() {
		// detect DNS servers, hidden behind systemd-resolved
		if err := h.detectRealDNS(conn); err != nil {
			return fmt.Errorf("failed to detect original DNS servers: %v", err)
		}
	}

	return updateNetworkManager(conn, h.dbusNmConnectionPath, h.dnsServers, h.dnsSuffixes)
}

func (h *Handler) restoreNetworkManager() {
	conn, err := newDbusConn()
	if err != nil {
		log.Errorf("%v", err)
		return
	}
	defer conn.Close()

	err = updateNetworkManager(conn, h.dbusNmConnectionPath, nil, nil)
	if err != nil {
		log.Errorf("%v", err)
		return
	}
	return
}
