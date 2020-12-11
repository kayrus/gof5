package dns

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/kayrus/gof5/pkg/config"

	"github.com/miekg/dns"
)

func Start(cfg *config.Config, errChan chan error) {
	log.Printf("Serving DNS proxy on %s:53", cfg.ListenDNS)
	log.Printf("Forwarding %q DNS requests to %q", cfg.DNS, cfg.F5Config.Object.DNS)
	log.Printf("Default DNS servers: %q", cfg.DNSServers)

	dnsUDPHandler := func(w dns.ResponseWriter, m *dns.Msg) {
		dnsHandler(w, m, cfg, "udp")
	}

	dnsTCPHandler := func(w dns.ResponseWriter, m *dns.Msg) {
		dnsHandler(w, m, cfg, "tcp")
	}

	go func() {
		srv := &dns.Server{Addr: cfg.ListenDNS.String() + ":53", Net: "udp", Handler: dns.HandlerFunc(dnsUDPHandler)}
		if err := srv.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("failed to set udp listener %s", err)
			return
		}
	}()
	go func() {
		srv := &dns.Server{Addr: cfg.ListenDNS.String() + ":53", Net: "tcp", Handler: dns.HandlerFunc(dnsTCPHandler)}
		if err := srv.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("failed to set tcp listener %s", err)
			return
		}
	}()
}

func dnsHandler(w dns.ResponseWriter, m *dns.Msg, cfg *config.Config, proto string) {
	c := new(dns.Client)
	c.Net = proto
	for _, suffix := range cfg.DNS {
		if strings.HasSuffix(m.Question[0].Name, suffix) {
			if cfg.Debug {
				log.Printf("Resolving %q using VPN DNS", m.Question[0].Name)
			}
			for _, s := range cfg.F5Config.Object.DNS {
				if err := handleCustom(w, m, c, s); err == nil {
					return
				}
			}
		}
	}
	for _, s := range cfg.DNSServers {
		if err := handleCustom(w, m, c, s); err == nil {
			return
		}
	}
}

func handleCustom(w dns.ResponseWriter, o *dns.Msg, c *dns.Client, ip net.IP) error {
	m := new(dns.Msg)
	o.CopyTo(m)
	r, _, err := c.Exchange(m, ip.String()+":53")
	if r == nil || err != nil {
		return fmt.Errorf("failed to resolve %q", m.Question[0].Name)
	}
	w.WriteMsg(r)
	return nil
}
