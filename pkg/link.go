package pkg

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

	//goCIDR "github.com/apparentlymart/go-cidr/cidr"
	"github.com/pion/dtls/v2"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"golang.zx2c4.com/wireguard/tun"
)

const (
	printGreen = "\033[1;32m%s\033[0m"
	bufferSize = 1500
	defaultMTU = 1420
)

type vpnLink struct {
	sync.Mutex
	name              string
	routesReady       bool
	serverRoutesReady bool
	link              netlink.Link
	iface             f5Tun
	conn              f5Conn
	ret               error
	errChan           chan error
	upChan            chan bool
	nameChan          chan string
	termChan          chan os.Signal
	serverIPs         []net.IP
	localIPv4         net.IP
	serverIPv4        net.IP
	localIPv6         net.IP
	serverIPv6        net.IP
	mtu               []byte
	mtuInt            uint16
	gateways          []net.IP
}

type f5Conn interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	Close() error
}

type f5Tun struct {
	tun.Device
	f5Conn
}

func (t *f5Tun) Read(b []byte) (int, error) {
	if t.Device != nil {
		// unix.IFF_NO_PI is not set, therefore we receive packet information
		n, err := t.Device.File().Read(b)
		if n < 4 {
			return 0, err
		}
		// shift slice to the left
		return copy(b[:n-4], b[4:n]), nil
	}
	return t.f5Conn.Read(b)
}

func (t *f5Tun) Write(b []byte) (int, error) {
	if t.Device != nil {
		return t.Device.Write(append(make([]byte, 4), b...), 4)
	}
	return t.f5Conn.Write(b)
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
func initConnection(server string, config *Config) (*vpnLink, error) {
	// TLS
	getURL := fmt.Sprintf("https://%s/myvpn?sess=%s&hostname=%s&hdlc_framing=%s&ipv4=%s&ipv6=%s&Z=%s",
		server,
		config.f5Config.Object.SessionID,
		base64.StdEncoding.EncodeToString(randomHostname(8)),
		Bool(config.Driver == "pppd"),
		config.f5Config.Object.IPv4,
		Bool(config.IPv6 && bool(config.f5Config.Object.IPv6)),
		config.f5Config.Object.UrZ,
	)

	serverIPs, err := net.LookupIP(server)
	if err != nil || len(serverIPs) == 0 {
		return nil, fmt.Errorf("failed to resolve %s: %s", server, err)
	}

	// define link channels
	link := &vpnLink{
		serverIPs: serverIPs,
		errChan:   make(chan error, 1),
		upChan:    make(chan bool, 1),
		nameChan:  make(chan string, 1),
		termChan:  make(chan os.Signal, 1),
	}

	if config.DTLS && config.f5Config.Object.TunnelDTLS {
		s := fmt.Sprintf("%s:%s", server, config.f5Config.Object.TunnelPortDTLS)
		log.Printf("Connecting to %s using DTLS", s)
		addr, err := net.ResolveUDPAddr("udp", s)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve UDP address: %s", err)
		}
		conf := &dtls.Config{
			InsecureSkipVerify: config.InsecureTLS,
		}
		link.conn, err = dtls.Dial("udp4", addr, conf)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %s:%s: %s", server, config.f5Config.Object.TunnelPortDTLS, err)
		}
	} else {
		conf := &tls.Config{
			InsecureSkipVerify: config.InsecureTLS,
		}
		link.conn, err = tls.Dial("tcp", fmt.Sprintf("%s:443", server), conf)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %s:443: %s", server, err)
		}

		req, err := http.NewRequest("GET", getURL, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create VPN session request: %s", err)
		}
		req.Header.Set("User-Agent", userAgentVPN)
		err = req.Write(link.conn)
		if err != nil {
			return nil, fmt.Errorf("failed to send VPN session request: %s", err)
		}

		if debug {
			log.Printf("URL: %s", getURL)
		}

		resp, err := http.ReadResponse(bufio.NewReader(link.conn), nil)
		if err != nil {
			return nil, fmt.Errorf("failed to get initial VPN connection response: %s", err)
		}
		resp.Body.Close()

		link.localIPv4 = net.ParseIP(resp.Header.Get("X-VPN-client-IP"))
		link.serverIPv4 = net.ParseIP(resp.Header.Get("X-VPN-server-IP"))
		link.localIPv6 = net.ParseIP(resp.Header.Get("X-VPN-client-IPv6"))
		link.serverIPv6 = net.ParseIP(resp.Header.Get("X-VPN-server-IPv6"))

		if debug {
			log.Printf("Client IP: %s", link.localIPv4)
			log.Printf("Server IP: %s", link.serverIPv4)
			if link.localIPv6 != nil {
				log.Printf("Client IPv6: %s", link.localIPv6)
			}
			if link.localIPv6 != nil {
				log.Printf("Server IPv6: %s", link.serverIPv6)
			}
		}
	}

	switch config.Driver {
	case "water":
		log.Printf("Using water module to create tunnel")
		device, err := water.New(water.Config{
			DeviceType: water.TUN,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create a %q interface: %s", water.TUN, err)
		}

		link.name = device.Name()
		log.Printf("Created %s interface", link.name)
		link.iface = f5Tun{f5Conn: device}
	case "wireguard":
		log.Printf("Using wireguard module to create tunnel")
		ifname := ""
		if runtime.GOOS == "darwin" {
			ifname = "utun"
		}
		device, err := tun.CreateTUN(ifname, defaultMTU)
		if err != nil {
			return nil, fmt.Errorf("failed to create an interface: %s", err)
		}

		link.name, err = device.Name()
		if err != nil {
			return nil, fmt.Errorf("failed to get an interface name: %s", err)
		}
		log.Printf("Created %s interface", link.name)
		link.iface = f5Tun{Device: device}
	}

	return link, nil
}

// error handler
func (l *vpnLink) errorHandler() {
	l.ret = <-l.errChan
	l.termChan <- syscall.SIGINT
}

func cidrContainsIPs(cidr *net.IPNet, ips []net.IP) bool {
	for _, ip := range ips {
		if cidr.Contains(ip) {
			//net, ok := goCIDR.PreviousSubnet(&net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, 17)
			//log.Printf("Previous: %s %t", net, ok)
			return true
		}
	}
	return false
}

// wait for pppd and config DNS and routes
func (l *vpnLink) waitAndConfig(config *Config) {
	var err error
	// wait for tun name
	l.name = <-l.nameChan
	if l.name == "" {
		l.errChan <- fmt.Errorf("failed to detect tunnel name")
		return
	}

	if config.Driver == "pppd" {
		// wait for tun up
		if !<-l.upChan {
			l.errChan <- fmt.Errorf("unexpected tun status event")
			return
		}
	}

	l.Lock()
	defer l.Unlock()

	if !config.DisableDNS {
		// define DNS servers, provided by F5
		log.Printf("Setting %s", resolvPath)
		if err = configureDNS(config); err != nil {
			l.errChan <- err
			return
		}

		if len(config.DNS) > 0 {
			startDNS(l, config)
		}
	}

	// set routes
	log.Printf("Setting routes on %s interface", l.name)
	if config.Driver != "pppd" {
		if err := setInterface(l); err != nil {
			l.errChan <- err
			return
		}
	}

	// set F5 gateway route
	for _, dst := range l.serverIPs {
		gws, err := routeGet(dst)
		if err != nil {
			l.errChan <- err
			return
		}
		for _, gw := range gws {
			if err = routeAdd(dst, gw, 1, l.name); err != nil {
				l.errChan <- err
				return
			}
			l.gateways = append(l.gateways, gw)
		}
		l.serverRoutesReady = true
	}

	// set custom routes
	routes := config.Routes
	if routes == nil {
		log.Printf("Applying routes, pushed from F5 VPN server")
		routes = config.f5Config.Object.Routes.GetNetworks()
	}
	for _, cidr := range routes {
		if debug {
			log.Printf("Adding %s route", cidr)
		}
		if false && cidrContainsIPs(cidr, l.serverIPs) {
			log.Printf("Skipping %s subnet", cidr)
			//continue
		}
		if err = routeAdd(cidr, nil, 0, l.name); err != nil {
			l.errChan <- err
			return
		}
	}
	l.routesReady = true
	log.Printf(printGreen, "Connection established")
}

// restore config
func (l *vpnLink) restoreConfig(config *Config) {
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

	if !config.DisableDNS {
		restoreDNS(config)
	}

	if l.serverRoutesReady {
		// remove F5 gateway route
		for _, dst := range l.serverIPs {
			for _, gw := range l.gateways {
				if err := routeDel(dst, gw, 1, l.name); err != nil {
					log.Print(err)
				}
			}
		}
	}

	if l.routesReady {
		if l.ret == nil {
			log.Printf("Removing routes from %s interface", l.name)
			routes := config.Routes
			if routes == nil {
				routes = config.f5Config.Object.Routes.GetNetworks()
			}
			for _, cidr := range routes {
				if false && cidrContainsIPs(cidr, l.serverIPs) {
					log.Printf("Skipping %s subnet", cidr)
					//continue
				}
				if err := routeDel(cidr, nil, 0, l.name); err != nil {
					log.Print(err)
				}
			}
		}
	}
}
