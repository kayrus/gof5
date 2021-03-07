// +build darwin

package resolv

import (
	"fmt"
	"net"
	"os/exec"
	"regexp"

	"github.com/kayrus/tuncfg/log"
)

var re = regexp.MustCompile(`(?m)^\(\d+\)\s+(.*)$`)

// TODO: use https://opensource.apple.com/source/configd/configd-293.5/SystemConfiguration.fproj/SCNetworkService.c.auto.html
// /System/Volumes/Data/System/Library/Frameworks/Python.framework/Versions/2.7/Extras/lib/python/PyObjC/SystemConfiguration
// https://gist.github.com/nigelkersten/633191
// https://gist.github.com/LiamHaworth/d50ce9167fe0377cd20d6585d77a70b4
// https://github.com/LiamHaworth/macos-golang
// https://github.com/mullvad/system-configuration-rs
// https://github.com/keybase/go-vendor-test/blob/master/github.com/keybase/go-kext/corefoundation.go
func resolveNetworkService() ([]string, error) {
	args := []string{
		"-listnetworkserviceorder",
	}
	v, err := exec.Command("networksetup", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get a list of interfaces: %s: %s: %s", args, v, err)
	}

	matches := re.FindAllStringSubmatch(string(v), -1)

	var names []string
	for _, v := range matches {
		if len(v) == 2 {
			names = append(names, v[1])
		}
	}

	if len(names) == 0 {
		return nil, fmt.Errorf("cannot find interfaces list")
	}

	return names, nil
}

func newHandler(_ string, dnsServers []net.IP, dnsSuffixes []string, _ bool) (*Handler, error) {
	names, err := resolveNetworkService()
	if err != nil {
		return nil, err
	}

	h := &Handler{
		names:       names,
		dnsServers:  dnsServers,
		dnsSuffixes: dnsSuffixes,
	}

	// read current resolv.conf
	err = h.parseResolvConf()
	if err != nil {
		return nil, err
	}

	return h, nil
}

func (h *Handler) Set() error {
	if len(h.dnsServers) == 0 && len(h.dnsSuffixes) == 0 {
		// nothing to do
		return nil
	}

	for _, name := range h.names {
		if len(h.dnsServers) > 0 {
			args := []string{
				"-setdnsservers",
				name,
			}
			for _, v := range h.dnsServers {
				args = append(args, v.String())
			}
			v, err := exec.Command("networksetup", args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to set %q DNS servers on %q: %s: %s: %s", h.dnsServers, name, args, v, err)
			}
		}

		if len(h.dnsSuffixes) > 0 {
			args := []string{
				"-setsearchdomains",
				name,
			}
			args = append(args, h.dnsSuffixes...)
			v, err := exec.Command("networksetup", args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to set %q DNS search prefix on %q: %s: %s: %s", h.dnsSuffixes, name, args, v, err)
			}
		}
	}

	return nil
}

func (h *Handler) Restore() {
	if len(h.dnsServers) == 0 && len(h.dnsSuffixes) == 0 {
		// nothing to do
		return
	}

	for _, name := range h.names {
		if len(h.dnsServers) > 0 {
			args := []string{
				"-setdnsservers",
				name,
				"empty",
			}
			v, err := exec.Command("networksetup", args...).CombinedOutput()
			if err != nil {
				log.Debugf("Failed to restore DNS servers on %q: %s: %s: %s", name, args, v, err)
			}
		}

		if len(h.dnsSuffixes) > 0 {
			args := []string{
				"-setsearchdomains",
				name,
				"empty",
			}
			v, err := exec.Command("networksetup", args...).CombinedOutput()
			if err != nil {
				log.Debugf("failed to restore DNS search prefix on %q: %s: %s: %s", name, args, v, err)
			}
		}
	}
}
