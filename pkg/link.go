package pkg

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"runtime"
	"strings"
	"sync"
	"syscall"

	//goCIDR "github.com/apparentlymart/go-cidr/cidr"
	"github.com/pion/dtls/v2"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

const (
	printGreen = "\033[1;32m%s\033[0m"
	bufferSize = 1500
)

type vpnLink struct {
	sync.Mutex
	name              string
	routesReady       bool
	serverRoutesReady bool
	link              netlink.Link
	iface             *water.Interface
	conn              myConn //*tls.Conn
	resolvConf        []byte
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
	peerGW            net.IP
}

type myConn interface {
	Write([]byte) (int, error)
	Read([]byte) (int, error)
	Close() error
}

// init a TLS connection
func initConnection(server string, config *Config, favorite *Favorite) (*vpnLink, error) {
	// TLS
	//purl, err := url.Parse(fmt.Sprintf("https://%s/myvpn?sess=%s&Z=%s&hdlc_framing=%s", server, favorite.Object.SessionID, favorite.Object.UrZ, hdlcFraming))
	// favorite.Object.IPv6 = false
	hostname := base64.StdEncoding.EncodeToString([]byte("my-hostname"))
	purl, err := url.Parse(fmt.Sprintf("https://%s/myvpn?sess=%s&hostname=%s&hdlc_framing=%s&ipv4=%s&ipv6=%s&Z=%s", server, favorite.Object.SessionID, hostname, config.PPPD, favorite.Object.IPv4, Bool(config.IPv6 && bool(favorite.Object.IPv6)), favorite.Object.UrZ))
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection VPN: %s", err)
	}

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

	if config.DTLS && favorite.Object.TunnelDTLS {
		s := fmt.Sprintf("%s:%s", server, favorite.Object.TunnelPortDTLS)
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
			return nil, fmt.Errorf("failed to dial %s:%s: %s", server, favorite.Object.TunnelPortDTLS, err)
		}
	} else {
		conf := &tls.Config{
			InsecureSkipVerify: config.InsecureTLS,
		}
		link.conn, err = tls.Dial("tcp", fmt.Sprintf("%s:443", server), conf)
		if err != nil {
			return nil, fmt.Errorf("failed to dial %s:443: %s", server, err)
		}

		str := fmt.Sprintf("GET %s HTTP/1.0\r\nUser-Agent: %s\r\nHost: %s\r\n\r\n", purl.RequestURI(), userAgentVPN, server)
		n, err := link.conn.Write([]byte(str))
		if err != nil {
			return nil, fmt.Errorf("failed to send VPN session request: %s", err)
		}

		if debug {
			log.Printf("URL: %s", str)
			log.Printf("Sent %d bytes", n)
		}

		// TODO: http.ReadResponse()
		buf := make([]byte, bufferSize)
		n, err = link.conn.Read(buf)
		if err != nil {
			return nil, fmt.Errorf("failed to get initial VPN connection response: %s", err)
		}

		for _, v := range strings.Split(string(buf), "\r\n") {
			if v := strings.SplitN(v, ":", 2); len(v) == 2 {
				switch v[0] {
				case "X-VPN-client-IP":
					link.localIPv4 = net.ParseIP(strings.TrimSpace(v[1]))
				case "X-VPN-server-IP":
					link.serverIPv4 = net.ParseIP(strings.TrimSpace(v[1]))
				case "X-VPN-client-IPv6":
					link.localIPv6 = net.ParseIP(strings.TrimSpace(v[1]))
				case "X-VPN-server-IPv6":
					link.serverIPv6 = net.ParseIP(strings.TrimSpace(v[1]))
				}
			}
		}

		if debug {
			log.Printf("Data: %s", buf)
			log.Printf("Received %d bytes", n)

			log.Printf("Client IP: %s", link.localIPv4)
			log.Printf("Server IP: %s", link.serverIPv4)
			if favorite.Object.IPv6 {
				log.Printf("Client IPv6: %s", link.localIPv6)
				log.Printf("Server IPv6: %s", link.serverIPv6)
			}
		}
	}

	if !config.PPPD {
		link.iface, err = water.New(water.Config{
			DeviceType: water.TUN,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create a %q interface: %s", water.TUN, err)
		}

		log.Printf("Created %s interface", link.iface.Name())
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
func (l *vpnLink) waitAndConfig(config *Config, fav *Favorite) {
	var err error
	// wait for tun name
	l.name = <-l.nameChan
	if l.name == "" {
		l.errChan <- fmt.Errorf("failed to detect tunnel name")
		return
	}

	if config.PPPD {
		// wait for tun up
		if !<-l.upChan {
			l.errChan <- fmt.Errorf("unexpected tun status event")
			return
		}
	}

	l.Lock()
	defer l.Unlock()
	// read current resolv.conf
	// reading it here in order to avoid conflicts, when the second VPN connection is established in parallel
	l.resolvConf, err = ioutil.ReadFile(resolvPath)
	if err != nil {
		l.errChan <- fmt.Errorf("cannot read %s: %s", resolvPath, err)
		return
	}

	// define DNS servers, provided by F5
	log.Printf("Setting %s", resolvPath)
	config.vpnServers = fav.Object.DNS
	dns := bytes.NewBufferString("# created by gof5 VPN client\n")
	if len(config.DNS) == 0 {
		log.Printf("Forwarding DNS requests to %q", config.vpnServers)
		for _, v := range fav.Object.DNS {
			if _, err = dns.WriteString("nameserver " + v.String() + "\n"); err != nil {
				l.errChan <- fmt.Errorf("failed to write DNS entry into buffer: %s", err)
				return
			}
		}
	} else {
		listenAddr := startDns(config, l.resolvConf)
		if _, err = dns.WriteString("nameserver " + listenAddr + "\n"); err != nil {
			l.errChan <- fmt.Errorf("failed to write DNS entry into buffer: %s", err)
			return
		}
		if fav.Object.DNSSuffix != "" {
			if _, err = dns.WriteString("search " + fav.Object.DNSSuffix + "\n"); err != nil {
				l.errChan <- fmt.Errorf("failed to write search DNS entry into buffer: %s", err)
				return
			}
		}
	}
	if err = ioutil.WriteFile(resolvPath, dns.Bytes(), 0644); err != nil {
		l.errChan <- fmt.Errorf("failed to write %s: %s", resolvPath, err)
		return
	}

	// set routes
	log.Printf("Setting routes on %s interface", l.name)
	if !config.PPPD {
		l.link, err = netlink.LinkByName(l.name)
		if err != nil {
			l.errChan <- fmt.Errorf("failed to detect %s interface: %s", l.name, err)
			return
		}
		err = netlink.LinkSetMTU(l.link, int(l.mtuInt))
		if err != nil {
			l.errChan <- fmt.Errorf("failed to set MTU on %s interface: %s", l.name, err)
			return
		}
		/*
			err = netlink.LinkSetARPOn(l.link)
			if err != nil {
				l.errChan <- fmt.Errorf("failed to set ARP on %s interface: %s", l.name, err)
				return
			}
			err = netlink.LinkSetAllmulticastOff(l.link)
			if err != nil {
				l.errChan <- fmt.Errorf("failed to set multicast on %s interface: %s", l.name, err)
				return
			}
		*/
		ipv4Addr := &netlink.Addr{
			IPNet: &net.IPNet{IP: l.localIPv4, Mask: net.CIDRMask(32, 32)},
			Peer:  &net.IPNet{IP: l.serverIPv4, Mask: net.CIDRMask(32, 32)},
		}
		err = netlink.AddrAdd(l.link, ipv4Addr)
		if err != nil {
			l.errChan <- fmt.Errorf("failed to set peer address on %s interface: %s", l.name, err)
			return
		}
		err = netlink.LinkSetUp(l.link)
		if err != nil {
			l.errChan <- fmt.Errorf("failed to set %s interface up: %s", l.name, err)
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

	if runtime.GOOS == "linux" {
		l.peerGW = l.localIPv4
	} else {
		l.peerGW = l.serverIPv4
	}

	// set custom routes
	for _, cidr := range config.Routes {
		if false && cidrContainsIPs(cidr, l.serverIPs) {
			log.Printf("Skipping %s subnet", cidr)
			//continue
		}
		if err = routeAdd(cidr, l.peerGW, 0, l.name); err != nil {
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

	if l.resolvConf != nil {
		log.Printf("Restoring original %s", resolvPath)
		if err := ioutil.WriteFile(resolvPath, l.resolvConf, 0644); err != nil {
			log.Printf("Failed to restore %s: %s", resolvPath, err)
		}
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
			for _, cidr := range config.Routes {
				if false && cidrContainsIPs(cidr, l.serverIPs) {
					log.Printf("Skipping %s subnet", cidr)
					//continue
				}
				if err := routeDel(cidr, l.peerGW, 0, l.name); err != nil {
					log.Print(err)
				}
			}
		}
	}
}
