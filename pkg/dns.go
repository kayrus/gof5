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

const listenAddr = "127.0.0.253"

// TODO: reverse DNS support, e.g. "in-addr.arpa"

var (
	// TODO: pass as a parameter to startDns func
	servers     []string
	dnsSuffixes []string
	origServers []string
)

func parseResolvConf(resolvConf []byte) {
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
			if len(f) > 1 && len(origServers) < 3 {
				if net.ParseIP(f[1]).To4() != nil {
					origServers = append(origServers, f[1])
				} else if net.ParseIP(f[1]).To16() != nil {
					origServers = append(origServers, f[1])
				}
			}
		}
	}
}

func startDns(resolvConf []byte) {
	parseResolvConf(resolvConf)
	log.Printf("Serving DNS proxy on %s:53", listenAddr)
	log.Printf("Forwarding %q DNS requests to %q", dnsSuffixes, servers)
	log.Printf("Default DNS servers: %q", origServers)
	go func() {
		srv := &dns.Server{Addr: listenAddr + ":53", Net: "udp", Handler: dns.HandlerFunc(dnsUdpHandler)}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set udp listener %s", err)
		}
	}()
	go func() {
		srv := &dns.Server{Addr: listenAddr + ":53", Net: "tcp", Handler: dns.HandlerFunc(dnsTcpHandler)}
		if err := srv.ListenAndServe(); err != nil {
			log.Fatalf("Failed to set tcp listener %s", err)
		}
	}()
}

func dnsHandler(w dns.ResponseWriter, m *dns.Msg, proto string) {
	c := new(dns.Client)
	c.Net = proto
	for _, suffix := range dnsSuffixes {
		if strings.HasSuffix(m.Question[0].Name, suffix) {
			if debug {
				log.Printf("Resoving %q using VPN DNS", m.Question[0].Name)
			}
			for _, s := range servers {
				if err := handleCustom(w, m, c, s); err == nil {
					return
				}
			}
		}
	}
	for _, s := range origServers {
		if err := handleCustom(w, m, c, s); err == nil {
			return
		}
	}
}

func handleCustom(w dns.ResponseWriter, o *dns.Msg, c *dns.Client, s string) error {
	m := new(dns.Msg)
	o.CopyTo(m)
	r, _, err := c.Exchange(m, s+":53")
	if r == nil || err != nil {
		return fmt.Errorf("failed to resolve %q", m.Question[0].Name)
	}
	w.WriteMsg(r)
	return nil
}

func dnsUdpHandler(w dns.ResponseWriter, m *dns.Msg) {
	dnsHandler(w, m, "udp")
}

func dnsTcpHandler(w dns.ResponseWriter, m *dns.Msg) {
	dnsHandler(w, m, "tcp")
}
