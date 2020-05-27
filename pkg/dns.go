package pkg

import (
	"bufio"
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/miekg/dns"
)

const defaultListenAddr = "127.0.0.1"

// TODO: reverse DNS support, e.g. "in-addr.arpa"

func parseResolvConf(config *Config, resolvConf []byte) {
	buf := bufio.NewReader(bytes.NewReader(resolvConf))
	for line, isPrefix, err := buf.ReadLine(); err == nil && isPrefix == false; line, isPrefix, err = buf.ReadLine() {
		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			continue
		}

		f := strings.FieldsFunc(string(line), splitFunc)
		if len(f) < 1 {
			continue
		}
		switch f[0] {
		case "nameserver":
			if len(f) > 1 && len(config.DNSServers) < 3 {
				if v := net.ParseIP(f[1]); v.To4() != nil {
					config.DNSServers = append(config.DNSServers, v)
				} else if v.To16() != nil {
					config.DNSServers = append(config.DNSServers, v)
				}
			}
		}
	}
}

func startDns(l *vpnLink, config *Config) string {
	if len(config.DNSServers) == 0 {
		parseResolvConf(config, l.resolvConf)
	}

	listenAddr := defaultListenAddr
	if config.ListenDNS != "" {
		listenAddr = config.ListenDNS
	}

	log.Printf("Serving DNS proxy on %s:53", listenAddr)
	log.Printf("Forwarding %q DNS requests to %q", config.DNS, config.vpnDNSServers)
	log.Printf("Default DNS servers: %q", config.DNSServers)

	dnsUdpHandler := func(w dns.ResponseWriter, m *dns.Msg) {
		dnsHandler(w, m, config, "udp")
	}

	dnsTcpHandler := func(w dns.ResponseWriter, m *dns.Msg) {
		dnsHandler(w, m, config, "tcp")
	}

	go func() {
		srv := &dns.Server{Addr: listenAddr + ":53", Net: "udp", Handler: dns.HandlerFunc(dnsUdpHandler)}
		if err := srv.ListenAndServe(); err != nil {
			l.errChan <- fmt.Errorf("failed to set udp listener %s", err)
			return
		}
	}()
	go func() {
		srv := &dns.Server{Addr: listenAddr + ":53", Net: "tcp", Handler: dns.HandlerFunc(dnsTcpHandler)}
		if err := srv.ListenAndServe(); err != nil {
			l.errChan <- fmt.Errorf("failed to set tcp listener %s", err)
			return
		}
	}()

	return listenAddr
}

func dnsHandler(w dns.ResponseWriter, m *dns.Msg, config *Config, proto string) {
	c := new(dns.Client)
	c.Net = proto
	for _, suffix := range config.DNS {
		if strings.HasSuffix(m.Question[0].Name, suffix) {
			if debug {
				log.Printf("Resolving %q using VPN DNS", m.Question[0].Name)
			}
			for _, s := range config.vpnDNSServers {
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
