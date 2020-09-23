// +build !darwin

package pkg

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
)

func configureDNS(config *Config) error {
	dns := bytes.NewBufferString("# created by gof5 VPN client\n")

	if len(config.DNS) == 0 {
		log.Printf("Forwarding DNS requests to %q", config.f5Config.Object.DNS)
		for _, v := range config.f5Config.Object.DNS {
			if _, err := dns.WriteString("nameserver " + v.String() + "\n"); err != nil {
				return fmt.Errorf("failed to write DNS entry into buffer: %s", err)
			}
		}
	} else {
		if _, err := dns.WriteString("nameserver " + config.ListenDNS.String() + "\n"); err != nil {
			return fmt.Errorf("failed to write DNS entry into buffer: %s", err)
		}
	}
	if len(config.f5Config.Object.DNSSuffix) > 0 {
		if _, err := dns.WriteString("search " + strings.Join(config.f5Config.Object.DNSSuffix, " ") + "\n"); err != nil {
			return fmt.Errorf("failed to write search DNS entry into buffer: %s", err)
		}
	}
	if err := ioutil.WriteFile(resolvPath, dns.Bytes(), 0644); err != nil {
		return fmt.Errorf("failed to write %s: %s", resolvPath, err)
	}

	return nil
}

func restoreDNS(config *Config) {
	if config.resolvConf != nil {
		log.Printf("Restoring original %s", resolvPath)
		if err := ioutil.WriteFile(resolvPath, config.resolvConf, 0644); err != nil {
			log.Printf("Failed to restore %s: %s", resolvPath, err)
		}
	}
}
