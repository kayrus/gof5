package dns

import (
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/kayrus/gof5/pkg/config"

	"github.com/miekg/dns"
)

func Start(cfg *config.Config, errChan chan error, tunDown chan struct{}) {
	dnsUDPHandler := func(w dns.ResponseWriter, m *dns.Msg) {
		dnsHandler(w, m, cfg, "udp")
	}

	dnsTCPHandler := func(w dns.ResponseWriter, m *dns.Msg) {
		dnsHandler(w, m, cfg, "tcp")
	}

	listen := net.JoinHostPort(cfg.ListenDNS.String(), "53")
	srvUDP := &dns.Server{
		Addr:    listen,
		Net:     "udp",
		Handler: dns.HandlerFunc(dnsUDPHandler),
	}
	srvTCP := &dns.Server{
		Addr:    listen,
		Net:     "tcp",
		Handler: dns.HandlerFunc(dnsTCPHandler),
	}

	go func() {
		if err := srvUDP.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("failed to set udp listener: %v", err)
			return
		}
	}()
	go func() {
		if err := srvTCP.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("failed to set tcp listener: %v", err)
			return
		}
	}()

	go func() {
		<-tunDown
		log.Printf("Shutting down DNS proxy")
		srvUDP.Shutdown()
		srvTCP.Shutdown()
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
	r, _, err := c.Exchange(m, net.JoinHostPort(ip.String(), "53"))
	if r == nil || err != nil {
		return fmt.Errorf("failed to resolve %q", m.Question[0].Name)
	}
	w.WriteMsg(r)
	return nil
}
