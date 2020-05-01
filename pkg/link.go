package pkg

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/vishvananda/netlink"
	"github.com/zaninime/go-hdlc"
)

// TODO: handle "fatal read pppd: read /dev/ptmx: input/output error"

const (
	printGreen = "\033[1;32m%s\033[0m"
)

type vpnLink struct {
	name        string
	routesReady bool
	link        netlink.Link
	resolvConf  []byte
	ret         error
	errChan     chan error
	upChan      chan bool
	nameChan    chan string
	termChan    chan os.Signal
}

// init a TLS connection
func initConnection(server string, config *Config, favorite *Favorite) (*tls.Conn, error) {
	// TLS
	//purl, err := url.Parse(fmt.Sprintf("https://%s/myvpn?sess=%s&Z=%s&hdlc_framing=%s", server, favorite.Object.SessionID, favorite.Object.UrZ, hdlcFraming))
	hostname := base64.StdEncoding.EncodeToString([]byte("my-hostname"))
	purl, err := url.Parse(fmt.Sprintf("https://%s/myvpn?sess=%s&hostname=%s&hdlc_framing=%s&ipv4=%s&ipv6=%s&Z=%s", server, favorite.Object.SessionID, hostname, config.HDLC, favorite.Object.IPv4, favorite.Object.IPv6, favorite.Object.UrZ))
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection VPN: %s", err)
	}
	conf := &tls.Config{
		InsecureSkipVerify: false,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", server), conf)
	if err != nil {
		return nil, fmt.Errorf("failed to dial %s:443: %s", server, err)
	}

	str := fmt.Sprintf("GET %s HTTP/1.0\r\nUser-Agent: %s\r\nHost: %s\r\n\r\n", purl.RequestURI(), userAgentVPN, server)
	n, err := conn.Write([]byte(str))
	if err != nil {
		return nil, fmt.Errorf("failed to send VPN session request: %s", err)
	}

	if debug {
		log.Printf("URL: %s", str)
		log.Printf("Sent %d bytes", n)
	}

	// TODO: http.ReadResponse()
	buf := make([]byte, 1500)
	n, err = conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to get initial VPN connection response: %s", err)
	}

	// informative part
	var clientIP, serverIP, clientIPv6, serverIPv6 string
	for _, v := range strings.Split(string(buf), "\r\n") {
		if v := strings.SplitN(v, ":", 2); len(v) == 2 {
			switch v[0] {
			case "X-VPN-client-IP":
				clientIP = strings.TrimSpace(v[1])
			case "X-VPN-server-IP":
				serverIP = strings.TrimSpace(v[1])
			case "X-VPN-client-IPv6":
				clientIPv6 = strings.TrimSpace(v[1])
			case "X-VPN-server-IPv6":
				serverIPv6 = strings.TrimSpace(v[1])
			}
		}
	}

	if debug {
		log.Printf("Data: %s", buf)
		log.Printf("Received %d bytes", n)

		log.Printf("Client IP: %s", clientIP)
		log.Printf("Server IP: %s", serverIP)
		if favorite.Object.IPv6 {
			log.Printf("Client IPv6: %s", clientIPv6)
			log.Printf("Server IPv6: %s", serverIPv6)
		}
	}

	return conn, nil
}

// http->tun
func (l *vpnLink) httpToTun(conn *tls.Conn, pppd *os.File) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-l.termChan:
			return
		default:
			rn, err := conn.Read(buf)
			if err != nil {
				l.errChan <- fmt.Errorf("fatal read http: %s", err)
				return
			}
			if debug {
				log.Printf("Read %d bytes from http:\n%s", rn, hex.Dump(buf[:rn]))
			}
			wn, err := pppd.Write(buf[:rn])
			if err != nil {
				l.errChan <- fmt.Errorf("fatal write to pppd: %s", err)
				return
			}
			if debug {
				log.Printf("Sent %d bytes to pppd", wn)
			}
		}
	}
}

// tun->http
func (l *vpnLink) tunToHttp(conn *tls.Conn, pppd *os.File) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-l.termChan:
			return
		default:
			rn, err := pppd.Read(buf)
			if err != nil {
				l.errChan <- fmt.Errorf("fatal read pppd: %s", err)
				return
			}
			if debug {
				log.Printf("Read %d bytes from pppd:\n%s", rn, hex.Dump(buf[:rn]))
			}
			wn, err := conn.Write(buf[:rn])
			if err != nil {
				l.errChan <- fmt.Errorf("fatal write to http: %s", err)
				return
			}
			if debug {
				log.Printf("Sent %d bytes to http", wn)
			}
		}
	}
}

// Encode F5 packet into pppd HDLC format
// http->tun
func (l *vpnLink) hdlcHttpToTun(conn *tls.Conn, pppd *os.File) {
	buf := make([]byte, 1500)
	for {
		select {
		case <-l.termChan:
			return
		default:
			rn, err := conn.Read(buf)
			if err != nil {
				l.errChan <- fmt.Errorf("fatal read http: %s", err)
				return
			}
			if debug {
				log.Printf("Read %d bytes from http:\n%s", rn, hex.Dump(buf[:rn]))
			}
			enc := hdlc.NewEncoder(pppd)
			// TODO: parse packet header
			wn, err := enc.WriteFrame(hdlc.Encapsulate(buf[6:rn], true))
			if err != nil {
				l.errChan <- fmt.Errorf("fatal write to pppd: %s", err)
				return
			}
			if debug {
				log.Printf("Sent %d bytes to pppd", wn)
			}
		}
	}
}

// Decode pppd HDLC format into F5 packet
// tun->http
func (l *vpnLink) hdlcTunToHttp(conn *tls.Conn, pppd *os.File) {
	for {
		select {
		case <-l.termChan:
			return
		default:
			dec := hdlc.NewDecoder(pppd)
			frame, err := dec.ReadFrame()
			if err != nil {
				l.errChan <- fmt.Errorf("fatal read pppd: %s", err)
				return
			}
			rn := len(frame.Payload)
			// TODO: use proper buffer + binary.BigEndian
			buf := append([]byte{0xf5, 0x00, 0x00, byte(rn), 0xff, 0x03}, frame.Payload...)
			if debug {
				log.Printf("Read %d bytes from pppd:\n%s", rn, hex.Dump(buf))
			}
			wn, err := conn.Write(buf)
			if err != nil {
				l.errChan <- fmt.Errorf("fatal write to http: %s", err)
				return
			}
			if debug {
				log.Printf("Sent %d bytes to http", wn)
			}
		}
	}
}

// error handler
func (l *vpnLink) errorHandler() {
	l.ret = <-l.errChan
	l.termChan <- syscall.SIGINT
}

// terminate on pppd termination
func (l *vpnLink) pppdWait(cmd *exec.Cmd) {
	err := cmd.Wait()
	if err != nil {
		l.errChan <- fmt.Errorf("pppd %s", err)
		return
	}
	l.errChan <- err
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

	// wait for tun up
	if !<-l.upChan {
		l.errChan <- fmt.Errorf("unexpected tun status event")
		return
	}

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
		startDns(config, l.resolvConf)
		if _, err = dns.WriteString("nameserver " + listenAddr + "\n"); err != nil {
			l.errChan <- fmt.Errorf("failed to write DNS entry into buffer: %s", err)
			return
		}
	}
	if err = ioutil.WriteFile(resolvPath, dns.Bytes(), 0644); err != nil {
		l.errChan <- fmt.Errorf("failed to write %s: %s", resolvPath, err)
		return
	}

	// set routes
	log.Printf("Setting routes on %s interface", l.name)
	l.link, err = netlink.LinkByName(l.name)
	if err != nil {
		l.errChan <- fmt.Errorf("failed to detect %s interface: %s", l.name, err)
		return
	}
	for _, cidr := range config.Routes {
		route := netlink.Route{LinkIndex: l.link.Attrs().Index, Dst: cidr}
		if err = netlink.RouteAdd(&route); err != nil {
			l.errChan <- fmt.Errorf("failed to set %s route on %s interface: %s", cidr.String(), l.name, err)
			return
		}
	}
	l.routesReady = true
	log.Printf(printGreen, "Connection established")
}

// restore config
func (l *vpnLink) restoreConfig(config *Config) {
	if l.resolvConf != nil {
		log.Printf("Restoring original %s", resolvPath)
		if err := ioutil.WriteFile(resolvPath, l.resolvConf, 0644); err != nil {
			log.Printf("Failed to restore %s: %s", resolvPath, err)
		}
	}

	if l.ret == nil && l.routesReady && l.link != nil {
		log.Printf("Removing routes from %s interface", l.name)
		for _, cidr := range config.Routes {
			route := netlink.Route{LinkIndex: l.link.Attrs().Index, Dst: cidr}
			if err := netlink.RouteDel(&route); err != nil {
				log.Printf("Failed to delete %s route from %s interface: %s", cidr.String(), l.name, err)
			}
		}
	}
}

// pppd log parser
func (l *vpnLink) pppdLogParser(stderr io.Reader) {
	scanner := bufio.NewScanner(stderr)
	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "Using interface") {
			if v := strings.FieldsFunc(strings.TrimSpace(scanner.Text()), splitFunc); len(v) > 0 {
				l.nameChan <- v[len(v)-1]
			}
		}
		if strings.Contains(scanner.Text(), "remote IP address") {
			l.upChan <- true
		}
		log.Printf(printGreen, scanner.Text())
	}
}
