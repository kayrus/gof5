// +build !darwin
// +build !windows

package resolv

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"github.com/kayrus/gof5/pkg/config"
)

var (
	resolvConfHeader = fmt.Sprintf("# created by gof5 VPN client (PID %d)\n", os.Getpid())
	resolvPathBak    = fmt.Sprintf("%s_gof5_%d", config.ResolvPath, os.Getpid())
)

func ConfigureDNS(cfg *config.Config, _ string) error {
	log.Printf("Setting %s", config.ResolvPath)

	dns := bytes.NewBufferString(resolvConfHeader)

	if len(cfg.DNS) == 0 {
		log.Printf("Forwarding DNS requests to %q", cfg.F5Config.Object.DNS)
		for _, v := range cfg.F5Config.Object.DNS {
			if _, err := dns.WriteString("nameserver " + v.String() + "\n"); err != nil {
				return fmt.Errorf("failed to write DNS entry into buffer: %s", err)
			}
		}
	} else {
		if _, err := dns.WriteString("nameserver " + cfg.ListenDNS.String() + "\n"); err != nil {
			return fmt.Errorf("failed to write DNS entry into buffer: %s", err)
		}
	}

	dnsSearch := append(cfg.DNSSearch, cfg.F5Config.Object.DNSSuffix...)
	if len(dnsSearch) > 0 {
		if _, err := dns.WriteString("search " + strings.Join(dnsSearch, " ") + "\n"); err != nil {
			return fmt.Errorf("failed to write search DNS entry into buffer: %s", err)
		}
	}

	// default "/etc/resolv.conf" permissions
	var perm os.FileMode = 0644
	if cfg.ResolvConf != nil {
		info, err := os.Stat(config.ResolvPath)
		if err != nil {
			return err
		}
		// reuse the original "/etc/resolv.conf" permissions
		perm = info.Mode()
		if err := os.Rename(config.ResolvPath, resolvPathBak); err != nil {
			return err
		}
	}

	if err := ioutil.WriteFile(config.ResolvPath, dns.Bytes(), perm); err != nil {
		return fmt.Errorf("failed to write %s: %s", config.ResolvPath, err)
	}

	return nil
}

func RestoreDNS(cfg *config.Config) {
	if cfg.ResolvConf == nil {
		// in case, when there was no "/etc/resolv.conf"
		log.Printf("Removing custom %s", config.ResolvPath)
		if err := os.Remove(config.ResolvPath); err != nil {
			log.Println(err)
		}
		return
	}

	log.Printf("Restoring original %s", config.ResolvPath)
	if err := os.Rename(resolvPathBak, config.ResolvPath); err != nil {
		log.Printf("Failed to restore %s: %s", config.ResolvPath, err)
	}
}
