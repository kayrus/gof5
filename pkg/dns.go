package pkg

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

// TODO: reverse DNS support, e.g. "in-addr.arpa"

func startDns(l *vpnLink, config *Config) {
	log.Printf("Serving DNS proxy on %s:53", config.ListenDNS)
	log.Printf("Forwarding %q DNS requests to %q", config.DNS, config.f5Config.Object.DNS)
	log.Printf("Default DNS servers: %q", config.DNSServers)

	dnsUdpHandler := func(w dns.ResponseWriter, m *dns.Msg) {
		dnsHandler(w, m, config, "udp")
	}

	dnsTcpHandler := func(w dns.ResponseWriter, m *dns.Msg) {
		dnsHandler(w, m, config, "tcp")
	}

	go func() {
		srv := &dns.Server{Addr: config.ListenDNS.String() + ":53", Net: "udp", Handler: dns.HandlerFunc(dnsUdpHandler)}
		if err := srv.ListenAndServe(); err != nil {
			l.errChan <- fmt.Errorf("failed to set udp listener %s", err)
			return
		}
	}()
	go func() {
		srv := &dns.Server{Addr: config.ListenDNS.String() + ":53", Net: "tcp", Handler: dns.HandlerFunc(dnsTcpHandler)}
		if err := srv.ListenAndServe(); err != nil {
			l.errChan <- fmt.Errorf("failed to set tcp listener %s", err)
			return
		}
	}()
}

func dnsHandler(w dns.ResponseWriter, m *dns.Msg, config *Config, proto string) {
	c := new(dns.Client)
	c.Net = proto
	for _, suffix := range config.DNS {
		if strings.HasSuffix(m.Question[0].Name, suffix) {
			if debug {
				log.Printf("Resolving %q using VPN DNS", m.Question[0].Name)
			}
			for _, s := range config.f5Config.Object.DNS {
				if err := handleCustom(w, m, c, s); err == nil {
					return
				}
			}
		}
	}
	for _, s := range config.DNSServers {
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
