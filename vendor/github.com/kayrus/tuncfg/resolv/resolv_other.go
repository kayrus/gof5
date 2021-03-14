// +build !darwin,!windows

package resolv

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"strings"

	"github.com/kayrus/tuncfg/log"
)

const (
	header      = "# created by %s (PID %d)\n"
	bakSuffixes = "%s_%s_%d"
)

func newHandler(name string, dnsServers []net.IP, dnsSuffixes []string, rewrite bool) (*Handler, error) {
	h := &Handler{
		name:        name,
		dnsServers:  dnsServers,
		dnsSuffixes: dnsSuffixes,
		rewrite:     rewrite,
		mode:        0644,
	}

	info, err := os.Stat(ResolvPath)
	if err == nil {
		// save the original "/etc/resolv.conf" permissions
		h.mode = info.Mode()
	}

	h.backupFilename = fmt.Sprintf(bakSuffixes, ResolvPath, AppName, os.Getpid())

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

	// NetworkManager has a higher priority
	if h.IsNetworkManager() {
		if v, ok := interface{}(h).(interface{ setNetworkManager() error }); ok {
			return v.setNetworkManager()
		}
	}

	if h.IsResolve() {
		if v, ok := interface{}(h).(interface{ setResolve() error }); ok {
			return v.setResolve()
		}
	}

	if h.IsShill() {
		if v, ok := interface{}(h).(interface{ setShill() error }); ok {
			return v.setShill()
		}
	}

	log.Debugf("Setting %s", ResolvPath)

	resolvConfHeader := fmt.Sprintf(header, AppName, os.Getpid())
	dns := bytes.NewBufferString(resolvConfHeader)
	for _, v := range h.dnsServers {
		if _, err := dns.WriteString("nameserver " + v.String() + "\n"); err != nil {
			return fmt.Errorf("failed to write DNS entry into buffer: %s", err)
		}
	}

	if len(h.dnsSuffixes) > 0 {
		if _, err := dns.WriteString("search " + strings.Join(h.dnsSuffixes, " ") + "\n"); err != nil {
			return fmt.Errorf("failed to write search DNS entry into buffer: %s", err)
		}
	}

	if len(h.dnsOptions) > 0 {
		if _, err := dns.WriteString("options " + strings.Join(h.dnsOptions, " ") + "\n"); err != nil {
			return fmt.Errorf("failed to write options DNS entry into buffer: %s", err)
		}
	}

	// we have a backup and don't rewrite the file
	if h.backup != nil && !h.rewrite {
		if err := os.Rename(ResolvPath, h.backupFilename); err != nil {
			return err
		}
	}

	log.Debugf("Forwarding DNS requests to %q", h.dnsServers)
	// when /etc/resolv.conf doesn't exist or rewrite is forced, just overwrite the file
	if err := ioutil.WriteFile(ResolvPath, dns.Bytes(), h.mode); err != nil {
		return fmt.Errorf("failed to write %s: %s", ResolvPath, err)
	}

	return nil
}

func (h *Handler) Restore() {
	if len(h.dnsServers) == 0 && len(h.dnsSuffixes) == 0 {
		// nothing to do
		return
	}

	// NetworkManager has a higher priority
	if h.IsNetworkManager() {
		if v, ok := interface{}(h).(interface{ restoreNetworkManager() }); ok {
			v.restoreNetworkManager()
			return
		}
	}

	if h.IsResolve() {
		if v, ok := interface{}(h).(interface{ restoreResolve() }); ok {
			v.restoreResolve()
			return
		}
	}

	if h.IsShill() {
		if v, ok := interface{}(h).(interface{ restoreShill() }); ok {
			v.restoreShill()
			return
		}
	}

	if h.backup == nil {
		// in case, when there was no "/etc/resolv.conf"
		log.Debugf("Removing custom %s", ResolvPath)
		if err := os.Remove(ResolvPath); err != nil {
			log.Errorf("%v", err)
		}
		return
	}

	log.Debugf("Restoring original %s", ResolvPath)

	if h.rewrite {
		if err := ioutil.WriteFile(ResolvPath, h.backup, h.mode); err != nil {
			log.Debugf("Failed to restore %s: %s", ResolvPath, err)
		}
		return
	}

	if err := os.Rename(h.backupFilename, ResolvPath); err != nil {
		log.Debugf("Failed to restore %s: %s", ResolvPath, err)
	}
}
