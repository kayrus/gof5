package link

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/kayrus/gof5/pkg/config"
	"github.com/kayrus/gof5/pkg/dns"

	"github.com/fatih/color"
	"github.com/kayrus/tuncfg/resolv"
	"github.com/kayrus/tuncfg/route"
	"github.com/kayrus/tuncfg/tun"
	"github.com/pion/dtls/v2"
)

const (
	// TUN MTU should not be bigger than buffer size
	bufferSize   = 1500
	userAgentVPN = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0; F5 Networks Client)"
)

var colorlog = log.New(color.Error, "", log.LstdFlags)

type vpnLink struct {
	sync.Mutex
	HTTPConn    io.ReadWriteCloser
	TermChan    chan os.Signal
	ErrChan     chan error
	PppdErrChan chan error
	iface       io.ReadWriteCloser
	name        string
	// pppUp is used to wait for the PPP handshake (wireguard only)
	pppUp chan struct{}
	// tunUp is used to wait for the TUN interface (wireguard and pppd)
	tunUp         chan struct{}
	serverIPs     []net.IP
	localIPv4     net.IP
	serverIPv4    net.IP
	localIPv6     net.IP
	serverIPv6    net.IP
	mtu           []byte
	mtuInt        uint16
	debug         bool
	routeHandler  *route.Handler
	resolvHandler *resolv.Handler
}

func randomHostname(n int) []byte {
	var letters = []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")

	rand.Seed(time.Now().UnixNano())

	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return b
}

// init a TLS connection
func InitConnection(server string, cfg *config.Config, tlsConfig *tls.Config) (*vpnLink, error) {
	getURL := fmt.Sprintf("https://%s/myvpn?sess=%s&hostname=%s&hdlc_framing=%s&ipv4=%s&ipv6=%s&Z=%s",
		server,
		cfg.F5Config.Object.SessionID,
		base64.StdEncoding.EncodeToString(randomHostname(8)),
		config.Bool(cfg.Driver == "pppd"),
		cfg.F5Config.Object.IPv4,
		config.Bool(cfg.IPv6 && bool(cfg.F5Config.Object.IPv6)),
		cfg.F5Config.Object.UrZ,
	)

	serverIPs, err := net.LookupIP(server)
	if err != nil || len(serverIPs) == 0 {
		return nil, fmt.Errorf("failed to resolve %s: %s", server, err)
	}

	// define link channels
	l := &vpnLink{
		TermChan:    make(chan os.Signal, 1),
		ErrChan:     make(chan error, 1),
		PppdErrChan: make(chan error, 1),
		serverIPs:   serverIPs,
		pppUp:       make(chan struct{}, 1),
		tunUp:       make(chan struct{}, 1),
		debug:       cfg.Debug,
	}

	if cfg.DTLS && cfg.F5Config.Object.TunnelDTLS {
		s := fmt.Sprintf("%s:%s", server, cfg.F5Config.Object.TunnelPortDTLS)
		log.Printf("Connecting to %s using DTLS", s)
		addr, err := net.ResolveUDPAddr("udp", s)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve UDP address: %s", err)
		}
		conf := &dtls.Config{
			RootCAs:            tlsConfig.RootCAs,
			Certificates:       tlsConfig.Certificates,
			InsecureSkipVerify: tlsConfig.InsecureSkipVerify,
			ServerName:         server,
		}
		l.HTTPConn, err = dtls.Dial("udp", addr, conf)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %s:%s: %s", server, cfg.F5Config.Object.TunnelPortDTLS, err)
		}
	} else {
		l.HTTPConn, err = tls.Dial("tcp", fmt.Sprintf("%s:443", server), tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %s:443: %s", server, err)
		}
	}

	req, err := http.NewRequest("GET", getURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create VPN session request: %s", err)
	}
	req.Header.Set("User-Agent", userAgentVPN)
	err = req.Write(l.HTTPConn)
	if err != nil {
		return nil, fmt.Errorf("failed to send VPN session request: %s", err)
	}

	if l.debug {
		log.Printf("URL: %s", getURL)
	}

	resp, err := http.ReadResponse(bufio.NewReader(l.HTTPConn), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get initial VPN connection response: %s", err)
	}
	resp.Body.Close()

	l.localIPv4 = net.ParseIP(resp.Header.Get("X-VPN-client-IP"))
	l.serverIPv4 = net.ParseIP(resp.Header.Get("X-VPN-server-IP"))
	l.localIPv6 = net.ParseIP(resp.Header.Get("X-VPN-client-IPv6"))
	l.serverIPv6 = net.ParseIP(resp.Header.Get("X-VPN-server-IPv6"))

	if l.debug {
		log.Printf("Client IP: %s", l.localIPv4)
		log.Printf("Server IP: %s", l.serverIPv4)
		if l.localIPv6 != nil {
			log.Printf("Client IPv6: %s", l.localIPv6)
		}
		if l.localIPv6 != nil {
			log.Printf("Server IPv6: %s", l.serverIPv6)
		}
	}

	return l, nil
}

func (l *vpnLink) createTunDevice() error {
	if l.mtuInt+tun.Offset > bufferSize {
		return fmt.Errorf("MTU exceeds the %d buffer limit", bufferSize)
	}

	log.Printf("Using wireguard module to create tunnel")
	ifname := ""
	switch runtime.GOOS {
	case "darwin":
		ifname = "utun"
	case "windows":
		ifname = "gof5"
	}

	local := &net.IPNet{
		IP:   l.localIPv4,
		Mask: net.CIDRMask(32, 32),
	}
	gw := &net.IPNet{
		IP:   l.serverIPv4,
		Mask: net.CIDRMask(32, 32),
	}
	tunDev, err := tun.OpenTunDevice(local, gw, ifname, int(l.mtuInt))
	if err != nil {
		return fmt.Errorf("failed to create an interface: %s", err)
	}
	l.name, err = tunDev.Name()
	if err != nil {
		if e := tunDev.Close(); e != nil {
			log.Printf("error closing interface: %v", e)
		}
		return fmt.Errorf("failed to get an interface name: %s", err)
	}

	log.Printf("Created %s interface", l.name)
	l.iface = &tun.Tunnel{NativeTun: tunDev}

	// can now process the traffic
	close(l.tunUp)

	return nil
}

// wait for pppd and config DNS and routes
func (l *vpnLink) WaitAndConfig(cfg *config.Config) {
	// wait for ppp handshake completed
	<-l.pppUp

	l.Lock()
	defer l.Unlock()

	var err error

	if cfg.Driver != "pppd" {
		// create TUN
		err = l.createTunDevice()
		if err != nil {
			l.ErrChan <- err
			return
		}
		defer func() {
			if err != nil && l.iface != nil {
				// destroy interface on error
				if e := l.iface.Close(); e != nil {
					log.Printf("error closing interface: %v", e)
				}
			}
		}()
	}

	if !cfg.DisableDNS {
		// this is used only in linux/freebsd to store /etc/resolv.conf backup
		resolv.AppName = "gof5"

		var dnsServers []net.IP
		dnsSuffixes := cfg.F5Config.Object.DNSSuffix
		if len(cfg.DNS) == 0 {
			// route everything through VPN gatewy
			dnsServers = cfg.F5Config.Object.DNS
		} else {
			// route only configured suffixes via local DNS proxy
			dnsServers = []net.IP{cfg.ListenDNS}
		}
		// define DNS servers, provided by F5
		l.resolvHandler, err = resolv.New(l.name, dnsServers, dnsSuffixes, cfg.RewriteResolv)
		if err != nil {
			l.ErrChan <- err
			return
		}

		if len(cfg.DNS) > 0 {
			// combine local network search with VPN gateway search
			dnsSuffixes = append(l.resolvHandler.GetOriginalSuffixes(), cfg.F5Config.Object.DNSSuffix...)
			log.Printf("Setting %q suffixes", dnsSuffixes)
			l.resolvHandler.SetSuffixes(dnsSuffixes)
		}

		err = l.resolvHandler.Set()
		if err != nil {
			l.ErrChan <- err
			return
		}

		// get default DNS servers, when config has empty list
		if len(cfg.DNSServers) == 0 {
			cfg.DNSServers = l.resolvHandler.GetOriginalDNS()
		}

		// TODO: check empty cfg.DNSServers
		if len(cfg.DNS) > 0 {
			dns.Start(cfg, l.ErrChan)
		}
	}

	// set routes
	log.Printf("Setting routes on %s interface", l.name)

	// set custom routes
	routes := cfg.Routes
	if routes == nil {
		log.Printf("Applying routes, pushed from F5 VPN server")
		routes = cfg.F5Config.Object.Routes
	}

	// exclude F5 gateway IPs
	for _, dst := range l.serverIPs {
		// exclude only ipv4
		if v := dst.To4(); v != nil {
			local := &net.IPNet{
				IP:   v,
				Mask: net.CIDRMask(32, 32),
			}
			routes.RemoveNet(local)
		}
	}

	var gw net.IP
	if runtime.GOOS == "windows" {
		// windows requires both gateway and interface name
		gw = l.serverIPv4
	}

	l.routeHandler, err = route.New(l.name, routes.GetNetworks(), gw, 0)
	if err != nil {
		l.ErrChan <- err
		return
	}
	l.routeHandler.Add()

	colorlog.Printf(color.HiGreenString("Connection established"))
}

// restore config
func (l *vpnLink) RestoreConfig(cfg *config.Config) {
	l.Lock()
	defer l.Unlock()

	if l.routeHandler != nil {
		log.Printf("Removing routes from %s interface", l.name)
		l.routeHandler.Del()
	}

	if !cfg.DisableDNS {
		if l.resolvHandler != nil {
			log.Printf("Restoring DNS settings")
			l.resolvHandler.Restore()
		}
	}

	if cfg.Driver != "pppd" {
		if l.iface != nil {
			err := l.iface.Close()
			if err != nil {
				log.Printf("error closing interface: %v", err)
			}
		}
	}
}
