package link

import (
	"bufio"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/kayrus/gof5/pkg/config"
	"github.com/kayrus/gof5/pkg/dns"
	"github.com/kayrus/gof5/pkg/resolv"
	"github.com/kayrus/gof5/pkg/route"

	"github.com/fatih/color"
	"github.com/pion/dtls/v2"
	"github.com/songgao/water"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	bufferSize   = 1500
	defaultMTU   = 1420
	userAgentVPN = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0; F5 Networks Client)"
)

var colorlog = log.New(color.Error, "", log.LstdFlags)

type vpnLink struct {
	sync.Mutex
	HTTPConn          f5Conn
	Ret               error
	TermChan          chan os.Signal
	name              string
	routesReady       bool
	serverRoutesReady bool
	dnsReady          bool
	iface             f5Tun
	errChan           chan error
	upChan            chan bool
	nameChan          chan string
	serverIPs         []net.IP
	localIPv4         net.IP
	serverIPv4        net.IP
	localIPv6         net.IP
	serverIPv6        net.IP
	mtu               []byte
	mtuInt            uint16
	gateways          []net.IP
	debug             bool
}

type f5Conn interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	Close() error
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
func InitConnection(server string, cfg *config.Config) (*vpnLink, error) {
	// TLS
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
		serverIPs: serverIPs,
		errChan:   make(chan error, 1),
		upChan:    make(chan bool, 1),
		nameChan:  make(chan string, 1),
		TermChan:  make(chan os.Signal, 1),
		debug:     cfg.Debug,
	}

	if cfg.DTLS && cfg.F5Config.Object.TunnelDTLS {
		s := fmt.Sprintf("%s:%s", server, cfg.F5Config.Object.TunnelPortDTLS)
		log.Printf("Connecting to %s using DTLS", s)
		addr, err := net.ResolveUDPAddr("udp", s)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve UDP address: %s", err)
		}
		conf := &dtls.Config{
			InsecureSkipVerify: cfg.InsecureTLS,
			ServerName:         server,
		}
		l.HTTPConn, err = dtls.Dial("udp", addr, conf)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %s:%s: %s", server, cfg.F5Config.Object.TunnelPortDTLS, err)
		}
	} else {
		conf := &tls.Config{
			InsecureSkipVerify: cfg.InsecureTLS,
		}
		l.HTTPConn, err = tls.Dial("tcp", fmt.Sprintf("%s:443", server), conf)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %s:443: %s", server, err)
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
	}

	switch cfg.Driver {
	case "water":
		log.Printf("Using water module to create tunnel")
		device, err := water.New(water.Config{
			DeviceType: water.TUN,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create a %q interface: %s", water.TUN, err)
		}

		l.name = device.Name()
		log.Printf("Created %s interface", l.name)
		l.iface = f5Tun{f5Conn: device}
	case "wireguard":
		log.Printf("Using wireguard module to create tunnel")
		ifname := ""
		switch runtime.GOOS {
		case "darwin":
			ifname = "utun"
		case "windows":
			ifname = "gof5"
		}
		device, err := tun.CreateTUN(ifname, defaultMTU)
		if err != nil {
			return nil, fmt.Errorf("failed to create an interface: %s", err)
		}

		l.name, err = device.Name()
		if err != nil {
			return nil, fmt.Errorf("failed to get an interface name: %s", err)
		}
		log.Printf("Created %s interface", l.name)
		l.iface = f5Tun{Device: device}
	}

	return l, nil
}

// error handler
func (l *vpnLink) ErrorHandler() {
	l.Ret = <-l.errChan
	l.TermChan <- syscall.SIGINT
}

// wait for pppd and config DNS and routes
func (l *vpnLink) WaitAndConfig(cfg *config.Config) {
	var err error
	// wait for tun name
	l.name = <-l.nameChan
	if l.name == "" {
		l.errChan <- fmt.Errorf("failed to detect tunnel name")
		return
	}

	if cfg.Driver == "pppd" {
		// wait for tun up
		if !<-l.upChan {
			l.errChan <- fmt.Errorf("unexpected tun status event")
			return
		}
	}

	l.Lock()
	defer l.Unlock()

	if !cfg.DisableDNS {
		// define DNS servers, provided by F5
		if err = resolv.ConfigureDNS(cfg, l.name); err != nil {
			l.errChan <- err
			return
		}

		if len(cfg.DNS) > 0 {
			dns.Start(cfg, l.errChan)
		}
		l.dnsReady = true
	}

	// set routes
	log.Printf("Setting routes on %s interface", l.name)
	if cfg.Driver != "pppd" {
		if err := route.SetInterface(l.name, l.localIPv4, l.serverIPv4, int(l.mtuInt)); err != nil {
			l.errChan <- err
			return
		}
	}

	// set F5 gateway route
	for _, dst := range l.serverIPs {
		gws, err := route.RouteGet(dst)
		if err != nil {
			l.errChan <- err
			return
		}
		for _, gw := range gws {
			if err = route.RouteAdd(dst, gw, 1, l.name); err != nil {
				l.errChan <- err
				return
			}
			l.gateways = append(l.gateways, gw)
		}
		l.serverRoutesReady = true
	}

	// set custom routes
	routes := cfg.Routes
	if routes == nil {
		log.Printf("Applying routes, pushed from F5 VPN server")
		routes = cfg.F5Config.Object.Routes.GetNetworks()
	}
	var gw net.IP
	if runtime.GOOS == "windows" {
		// windows requires both gateway and interface name
		gw = l.serverIPv4
	}
	for _, cidr := range routes {
		if l.debug {
			log.Printf("Adding %s route", cidr)
		}
		if err = route.RouteAdd(cidr, gw, 0, l.name); err != nil {
			l.errChan <- err
			return
		}
	}
	l.routesReady = true
	colorlog.Printf(color.HiGreenString("Connection established"))
}

// restore config
func (l *vpnLink) RestoreConfig(cfg *config.Config) {
	l.Lock()
	defer l.Unlock()

	defer func() {
		if l.iface.Device != nil {
			l.iface.Device.Close()
		}
		if l.iface.f5Conn != nil {
			l.iface.f5Conn.Close()
		}
	}()

	if !cfg.DisableDNS {
		if l.dnsReady {
			resolv.RestoreDNS(cfg)
		}
	}

	if l.serverRoutesReady {
		// remove F5 gateway route
		for _, dst := range l.serverIPs {
			for _, gw := range l.gateways {
				if err := route.RouteDel(dst, gw, 1, l.name); err != nil {
					log.Print(err)
				}
			}
		}
	}

	if l.routesReady {
		if l.Ret == nil {
			log.Printf("Removing routes from %s interface", l.name)
			routes := cfg.Routes
			if routes == nil {
				routes = cfg.F5Config.Object.Routes.GetNetworks()
			}
			for _, cidr := range routes {
				if err := route.RouteDel(cidr, nil, 0, l.name); err != nil {
					log.Print(err)
				}
			}
		}
	}
}
