package pkg

import (
	"fmt"
	"log"
	"strings"

	"github.com/miekg/dns"
)

const listenAddr = "127.0.0.253"

var (
	servers     []string
	dnsSuffixes []string
)

func startDns() {
	log.Printf("Serving DNS proxy on %s:53", listenAddr)
	log.Printf("Forwarding %q DNS requests to %q", dnsSuffixes, servers)
	go func() {
		srv := &dns.Server{Addr: listenAddr + ":53", Net: "udp", Handler: dns.HandlerFunc(dnsUdpHandler)}
		err := srv.ListenAndServe()
		if err != nil {
			log.Fatalf("Failed to set udp listener %s", err)
		}
	}()
	go func() {
		srv := &dns.Server{Addr: listenAddr + ":53", Net: "tcp", Handler: dns.HandlerFunc(dnsTcpHandler)}
		err := srv.ListenAndServe()
		if err != nil {
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
	// TODO: use/parse default /etc/resolv.conf
	handleCustom(w, m, c, "8.8.8.8")
}

func handleCustom(w dns.ResponseWriter, o *dns.Msg, c *dns.Client, s string) error {
	m := new(dns.Msg)
	o.CopyTo(m)
	v := m.Question[0].Name
	m.Question[0].Name = strings.ToUpper(v)
	r, _, err := c.Exchange(m, s+":53")
	if r == nil || err != nil {
		return fmt.Errorf("failed to resolve %q", v)
	}
	if len(r.Question) > 0 {
		r.Question[0].Name = strings.ToLower(r.Question[0].Name)
		for i := 0; i < len(r.Answer); i++ {
			r.Answer[i].Header().Name = strings.ToLower(r.Answer[i].Header().Name)
		}
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
