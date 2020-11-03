// +build !darwin

package pkg

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
)

var (
	resolvConfHeader = fmt.Sprintf("# created by gof5 VPN client (PID %d)\n", os.Getpid())
	resolvPathBak    = fmt.Sprintf("%s_gof5_%d", resolvPath, os.Getpid())
)

func configureDNS(config *Config) error {
	dns := bytes.NewBufferString(resolvConfHeader)

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

      // default "/etc/resolv.conf" permissions
	var perm os.FileMode = 0644
	if config.resolvConf != nil {
		info, err := os.Stat(resolvPath)
		if err != nil {
			return err
		}
		// reuse the original "/etc/resolv.conf" permissions
		perm = info.Mode()
		if err := os.Rename(resolvPath, resolvPathBak); err != nil {
			return err
		}
	}

	if err := ioutil.WriteFile(resolvPath, dns.Bytes(), perm); err != nil {
		return fmt.Errorf("failed to write %s: %s", resolvPath, err)
	}

	return nil
}

func restoreDNS(config *Config) {
	if config.resolvConf == nil {
		// in case, when there was no "/etc/resolv.conf"
		log.Printf("Removing custom %s", resolvPath)
		if err := os.Remove(resolvPath); err != nil {
			log.Println(err)
		}
		return
	}

	log.Printf("Restoring original %s", resolvPath)
	if err := os.Rename(resolvPathBak, resolvPath); err != nil {
		log.Printf("Failed to restore %s: %s", resolvPath, err)
	}
}
