// +build darwin

package resolv

import (
	"fmt"
	"log"
	"os/exec"
	"regexp"

	"github.com/kayrus/gof5/pkg/config"
)

var re = regexp.MustCompile(`\(\d+\)\s(.*)`)

func getInterfaces() ([]string, error) {
	args := []string{
		"-listnetworkserviceorder",
	}
	v, err := exec.Command("networksetup", args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to get a list of interfaces: %s: %s: %s", args, v, err)
	}

	matches := re.FindAllStringSubmatch(string(v), -1)

	if len(matches) == 0 {
		return nil, fmt.Errorf("cannot find interfaces list")
	}

	var res []string
	for _, v := range matches {
		if len(v) == 2 {
			res = append(res, v[1])
		}
	}

	return res, nil
}

func ConfigureDNS(cfg *config.Config) error {
	ifaces, err := getInterfaces()
	if err != nil {
		return err
	}

	for _, iface := range ifaces {
		if len(cfg.DNS) == 0 {
			args := []string{
				"-setdnsservers",
				iface,
			}
			for _, v := range cfg.F5Config.Object.DNS {
				args = append(args, v.String())
			}
			v, err := exec.Command("networksetup", args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to set %q DNS servers on %q: %s: %s: %s", cfg.F5Config.Object.DNS, iface, args, v, err)
			}
		} else {
			args := []string{
				"-setdnsservers",
				iface,
				cfg.ListenDNS.String(),
			}
			v, err := exec.Command("networksetup", args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to set %q DNS server on %q: %s: %s: %s", cfg.ListenDNS.String(), iface, args, v, err)
			}
		}

		dnsSearch := append(cfg.DNSSearch, cfg.F5Config.Object.DNSSuffix...)
		if len(dnsSearch) > 0 {
			args := []string{
				"-setsearchdomains",
				iface,
			}
			args = append(args, dnsSearch...)
			v, err := exec.Command("networksetup", args...).CombinedOutput()
			if err != nil {
				return fmt.Errorf("failed to set %q DNS search prefix on %q: %s: %s: %s", dnsSearch, iface, args, v, err)
			}
		}
	}

	return nil
}

func RestoreDNS(cfg *config.Config) {
	ifaces, err := getInterfaces()
	if err != nil {
		log.Printf("Failed to restore DNS settings: %s", err)
		return
	}

	for _, iface := range ifaces {
		args := []string{
			"-setdnsservers",
			iface,
			"empty",
		}
		v, err := exec.Command("networksetup", args...).CombinedOutput()
		if err != nil {
			log.Printf("Failed to restore DNS servers on %q: %s: %s: %s", iface, args, v, err)
		}

		if len(cfg.F5Config.Object.DNSSuffix) > 0 {
			args = []string{
				"-setsearchdomains",
				iface,
				"empty",
			}
			v, err := exec.Command("networksetup", args...).CombinedOutput()
			if err != nil {
				log.Printf("failed to restore DNS search prefix on %q: %s: %s: %s", iface, args, v, err)
			}
		}
	}
}
