// +build windows

package resolv

import (
	"fmt"
	"os/exec"

	"github.com/kayrus/gof5/pkg/config"
	"github.com/kayrus/gof5/pkg/util"
)

var ifIndex int

func ConfigureDNS(cfg *config.Config, iface string) error {
	var err error
	if ifIndex == 0 {
		if ifIndex, err = util.GetIfID(iface); err != nil {
			return err
		}
	}

	if len(cfg.DNS) == 0 {
		for i, v := range cfg.F5Config.Object.DNS {
			var action string
			if i == 0 {
				action = "set"
			} else {
				action = "add"
			}
			args := []string{
				"interface",
				"ip",
				action,
				"dns",
				fmt.Sprintf("name=%d", ifIndex),
			}
			if i == 0 {
				args = append(args, "static")
			}
			args = append(args, v.String())
			if i > 0 {
				args = append(args, fmt.Sprintf("index=%d", i+1))
			}
			v, err := exec.Command("netsh.exe", args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to set %q DNS server on %q: %s: %s: %s", v, iface, args, v, err)
			}
		}
	} else {
		args := []string{
			"interface",
			"ip",
			"set",
			"dns",
			fmt.Sprintf("name=%d", ifIndex),
			"static",
			cfg.ListenDNS.String(),
		}
		v, err := exec.Command("netsh.exe", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to set %q DNS server on %q: %s: %s: %s", cfg.ListenDNS.String(), iface, args, v, err)
		}
	}

	dnsSearch := append(cfg.DNSSearch, cfg.F5Config.Object.DNSSuffix...)
	if len(dnsSearch) > 0 {
		args := []string{
			"Set-DnsClient",
			"-InterfaceIndex",
			fmt.Sprintf("%d", ifIndex),
			"-ConnectionSpecificSuffix",
		}
		args = append(args, dnsSearch...)
		v, err := exec.Command("powershell.exe", args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("failed to set %q DNS search prefix on %q: %s: %s: %s", dnsSearch, iface, args, v, err)
		}
	}

	return nil
}

func RestoreDNS(cfg *config.Config) {
	// nothing to do in windows, because DNS are interface based
}
