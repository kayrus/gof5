// +build darwin

package pkg

import (
	"fmt"
	"log"
	"os/exec"
)

func configureDNS(config *Config) error {
	if len(config.DNS) == 0 {
		args := []string{
			"-setdnsservers",
			"Wi-Fi",
		}
		for _, v := range config.f5Config.Object.DNS {
			args = append(args, v.String())
		}
		v, err := exec.Command("networksetup", args...).Output()
		if err != nil {
			return fmt.Errorf("failed to set %q DNS servers: %s: %s", args, v, err)
		}
	} else {
		v, err := exec.Command("networksetup", "-setdnsservers", "Wi-Fi", config.ListenDNS.String()).Output()
		if err != nil {
			return fmt.Errorf("failed to set %q DNS server: %s: %s", config.ListenDNS.String(), v, err)
		}
	}

	if config.f5Config.Object.DNSSuffix != "" {
		v, err := exec.Command("networksetup", "-setsearchdomains", "Wi-Fi", config.f5Config.Object.DNSSuffix).Output()
		if err != nil {
			return fmt.Errorf("failed to set %q DNS search prefix: %s: %s", config.f5Config.Object.DNSSuffix, v, err)
		}
	}

	return nil
}

func deConfigureDNS(config *Config) {
	v, err := exec.Command("networksetup", "-setdnsservers", "Wi-Fi", "empty").Output()
	if err != nil {
		log.Printf("Failed to restore DNS servers: %s: %s", v, err)
	}

	if config.f5Config.Object.DNSSuffix != "" {
		v, err := exec.Command("networksetup", "-setsearchdomains", "Wi-Fi", "empty").Output()
		if err != nil {
			log.Printf("failed to restore DNS search prefix: %s: %s", v, err)
		}
	}
}
