package pkg

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"syscall"

	//goCIDR "github.com/apparentlymart/go-cidr/cidr"
	"github.com/jackpal/gateway"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
	"github.com/zaninime/go-hdlc"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// TODO: handle "fatal read pppd: read /dev/ptmx: input/output error"

const (
	printGreen = "\033[1;32m%s\033[0m"
	bufferSize = 1500
)

type vpnLink struct {
	name        string
	routesReady bool
	link        netlink.Link
	iface       *water.Interface
	conn        *tls.Conn
	resolvConf  []byte
	ret         error
	errChan     chan error
	upChan      chan bool
	nameChan    chan string
	termChan    chan os.Signal
	serverIPs   []net.IP
	localIPv4   net.IP
	serverIPv4  net.IP
	localIPv6   net.IP
	serverIPv6  net.IP
	mtu         []byte
	mtuInt      uint16
}

// init a TLS connection
func initConnection(server string, config *Config, favorite *Favorite) (*vpnLink, error) {
	// TLS
	//purl, err := url.Parse(fmt.Sprintf("https://%s/myvpn?sess=%s&Z=%s&hdlc_framing=%s", server, favorite.Object.SessionID, favorite.Object.UrZ, hdlcFraming))
	// favorite.Object.IPv6 = false
	hostname := base64.StdEncoding.EncodeToString([]byte("my-hostname"))
	purl, err := url.Parse(fmt.Sprintf("https://%s/myvpn?sess=%s&hostname=%s&hdlc_framing=%s&ipv4=%s&ipv6=%s&Z=%s", server, favorite.Object.SessionID, hostname, config.PPPD, favorite.Object.IPv4, favorite.Object.IPv6, favorite.Object.UrZ))
	if err != nil {
		return nil, fmt.Errorf("failed to parse connection VPN: %s", err)
	}
	conf := &tls.Config{
		InsecureSkipVerify: config.InsecureTLS,
	}

	serverIPs, err := net.LookupIP(server)
	if err != nil || len(serverIPs) == 0 {
		return nil, fmt.Errorf("failed to resolve %s: %s", server, err)
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
	buf := make([]byte, bufferSize)
	n, err = conn.Read(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to get initial VPN connection response: %s", err)
	}

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

	// define link channels
	link := &vpnLink{
		conn:      conn,
		serverIPs: serverIPs,
		errChan:   make(chan error, 1),
		upChan:    make(chan bool, 1),
		nameChan:  make(chan string, 1),
		termChan:  make(chan os.Signal, 1),
	}

	if !config.PPPD {
		iface, err := water.New(water.Config{
			DeviceType: water.TUN,
		})
		if err != nil {
			log.Fatal(err)
		}

		link.iface = iface
		log.Printf("Created %s interface", iface.Name())
	}

	return link, nil
}

func ipRun(args ...string) {
	err := exec.Command("/sbin/ip", args...).Run()
	if nil != err {
		log.Printf("Error running /sbin/ip %q: %s", args, err)
		//log.Fatalf("Error running /sbin/ip %q: %s", args, err)
	}
}

func (l *vpnLink) decodeHDLC(buf []byte, src string) {
	tmp := bytes.NewBuffer(buf)
	frame, err := hdlc.NewDecoder(tmp).ReadFrame()
	if err != nil {
		log.Printf("fatal decode HDLC frame from %s: %s", src, err)
		return
		/*
			l.errChan <- fmt.Errorf("fatal decode HDLC frame from %s: %s", source, err)
			return
		*/
	}
	log.Printf("Decoded %t prefix HDLC frame from %s:\n%s", frame.HasAddressCtrlPrefix, src, hex.Dump(frame.Payload))
	h, err := ipv4.ParseHeader(frame.Payload[:])
	if err != nil {
		log.Printf("fatal to parse TCP header from %s: %s", src, err)
		return
		/*
			l.errChan <- fmt.Errorf("fatal to parse TCP header: %s", err)
			return
		*/
	}
	log.Printf("TCP: %s", h)
}

// http->tun
func (l *vpnLink) pppdHttpToTun(pppd *os.File) {
	buf := make([]byte, bufferSize)
	for {
		select {
		case <-l.termChan:
			return
		default:
			rn, err := l.conn.Read(buf)
			if err != nil {
				l.errChan <- fmt.Errorf("fatal read http: %s", err)
				return
			}
			if debug {
				l.decodeHDLC(buf[:rn], "http")
				//log.Printf("Read %d bytes from http:\n%s", rn, hex.Dump(buf[:rn]))
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
func (l *vpnLink) pppdTunToHttp(pppd *os.File) {
	buf := make([]byte, bufferSize)
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
				l.decodeHDLC(buf[:rn], "pppd")
			}
			wn, err := l.conn.Write(buf[:rn])
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

func fromF5(link *vpnLink, buf []byte) error {
	l := uint16(len(buf))
	if l < 5 {
		return fmt.Errorf("data is too small: %d", l)
	}
	if !(buf[0] == 0xf5 && buf[1] == 00) {
		return fmt.Errorf("incorrect F5 header: %x", buf[:4])
	}

	// read 4 bytes (uint32 size) of the next element size
	var headerLen uint16 = 4
	pkglen := binary.BigEndian.Uint16(buf[2:4]) + headerLen

	if pkglen == l {
		processPPP(link, buf[headerLen:pkglen])
		return nil
	}

	if pkglen < l {
		// recursively process multiple F5 packets in one PPP packet
		return fromF5(link, buf[pkglen:])
	}

	// read the tails
	newBuf := make([]byte, bufferSize)
	rn, err := link.conn.Read(newBuf)
	if err != nil {
		return fmt.Errorf("fatal read http: %s", err)
	}
	if debug {
		log.Printf("Read %d bytes from http:\n%s", rn, hex.Dump(newBuf[:rn]))
	}
	return fromF5(link, append(buf[:], newBuf[:rn]...))
}

func readBuf(buf, sep []byte) []byte {
	n := bytes.Index(buf, sep)
	if n == 0 {
		return buf[len(sep):]
	}
	return nil
}

func toF5andSend(conn *tls.Conn, buf []byte) error {
	data, err := toF5(buf)
	if err != nil {
		return err
	}
	if debug {
		log.Printf("Sending:\n%s", hex.Dump(data))
	}
	_, err = conn.Write(data)
	return err
}

var (
	ppp         = []byte{0xff, 0x03}
	pppLCP      = []byte{0xc0, 0x21}
	pppIPCP     = []byte{0x80, 0x21}
	pppIPv6CP   = []byte{0x80, 0x57}
	// LCP auth
	mtuRequest  = []byte{0x00, 0x18}
	// Link-Discriminator
	terminate   = []byte{0x00, 0x17}
	// 
	mtuResponse = []byte{0x00, 0x12}
	protoRej    = []byte{0x00, 0x2c}
	mtuHeader   = []byte{0x01, 0x04}
	mtuSize     = 2
	ipv6type    = []byte{0x00, 0x0e}
	ipv4type    = []byte{0x00, 0x0a}
	v4          = []byte{0x06}
	v6          = []byte{0x0a}
	pfc         = []byte{0x07, 0x02}
	acfc        = []byte{0x08, 0x02}
	accm        = []byte{0x02, 0x06, 0x00, 0x00, 0x00, 0x00}
	magicHeader = []byte{0x05, 0x06}
	magicSize   = 4
	ipv4header  = []byte{0x21}
	ipv6header  = []byte{0x57}
	//
	confRequest = []byte{0x01}
	confAck     = []byte{0x02}
	confNack    = []byte{0x03}
	confRej     = []byte{0x04}
	confTermReq = []byte{0x05}
	protoReject = []byte{0x08}
	echoReq     = []byte{0x09}
	echoRep     = []byte{0x0a}
)

func bytesToIPv4(bytes []byte) net.IP {
	return net.IP(append(bytes[:0:0], bytes...))
}

func bytesToIPv6(bytes []byte) net.IP {
	return net.IP(append([]byte{0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, append(bytes[:0:0], bytes...)...))
}

func processPPP(link *vpnLink, buf []byte) {
	// process ipv4 traffic
	if v := readBuf(buf, ipv4header); v != nil {
		if debug {
			log.Printf("Read parsed ipv4 %d bytes from http:\n%s", len(v), hex.Dump(v))
			header, _ := ipv4.ParseHeader(v)
			log.Printf("ipv4 from http: %s", header)
		}

		wn, err := link.iface.Write(v)
		if err != nil {
			log.Fatalf("Fatal write to tun: %s", err)
		}
		if debug {
			log.Printf("Sent %d bytes to tun", wn)
		}
		return
	}

	// process ipv6 traffic
	if v := readBuf(buf, ipv6header); v != nil {
		if debug {
			log.Printf("Read parsed ipv6 %d bytes from http:\n%s", len(v), hex.Dump(v))
			header, _ := ipv6.ParseHeader(v)
			log.Printf("ipv6 from http: %s", header)
		}

		wn, err := link.iface.Write(v)
		if err != nil {
			log.Fatalf("Fatal write to tun: %s", err)
		}
		if debug {
			log.Printf("Sent %d bytes to tun", wn)
		}
		return
	}

	// TODO: support IPv4 only
	if v := readBuf(buf, pppIPCP); v != nil {
		if v := readBuf(v, confRequest); v != nil {
			id := v[0]
			if v := readBuf(v[1:], ipv4type); v != nil {
				id2 := v[0]
				if v := readBuf(v[1:], v4); v != nil {
					link.serverIPv4 = bytesToIPv4(v)
					log.Printf("id: %d, id2: %d, Remote IPv4 requested: %s", id, id2, link.serverIPv4)

					doResp := &bytes.Buffer{}
					doResp.Write(ppp)
					doResp.Write(pppIPCP)
					//
					doResp.Write(confAck)
					doResp.WriteByte(id)
					doResp.Write(ipv4type)
					doResp.WriteByte(id2)
					doResp.Write(v4)
					doResp.Write(v)

					toF5andSend(link.conn, doResp.Bytes())

					doResp = &bytes.Buffer{}
					doResp.Write(ppp)
					doResp.Write(pppIPCP)
					//
					doResp.Write(confRequest)
					doResp.WriteByte(id)
					doResp.Write(ipv4type)
					doResp.WriteByte(id2)
					doResp.Write(v4)
					for i := 0; i < 4; i++ {
						doResp.WriteByte(0)
					}

					toF5andSend(link.conn, doResp.Bytes())

					return
				}
			}
		}
		if v := readBuf(v, confAck); v != nil {
			id := v[0]
			if v := readBuf(v[1:], ipv4type); v != nil {
				id2 := v[0]
				if v := readBuf(v[1:], v4); v != nil {
					link.localIPv4 = bytesToIPv4(v)
					log.Printf("id: %d, id2: %d, Local IPv4 acknowledged: %s", id, id2, link.localIPv4)

					link.nameChan <- link.iface.Name()
					link.upChan <- true

					return
				}
			}
		}
		if v := readBuf(v, confNack); v != nil {
			id := v[0]
			if v := readBuf(v[1:], ipv4type); v != nil {
				id2 := v[0]
				if v := readBuf(v[1:], v4); v != nil {
					log.Printf("id: %d, id2: %d, Local IPv4 not acknowledged: %s", id, id2, bytesToIPv4(v))

					doResp := &bytes.Buffer{}
					doResp.Write(ppp)
					doResp.Write(pppIPCP)
					//
					doResp.Write(confRequest)
					doResp.WriteByte(id)
					doResp.Write(ipv4type)
					doResp.WriteByte(id2)
					doResp.Write(v4)
					doResp.Write(v)

					toF5andSend(link.conn, doResp.Bytes())

					return
				}
			}
		}
	}

	// pppIPv6CP
	if v := readBuf(buf, pppIPv6CP); v != nil {
		if v := readBuf(v, confRequest); v != nil {
			id := v[0]
			if v := readBuf(v[1:], ipv6type); v != nil {
				id2 := v[0]
				if v := readBuf(v[1:], v6); v != nil {
					link.serverIPv6 = bytesToIPv6(v)
					log.Printf("id: %d, id2: %d, Remote IPv6 requested: %s", id, id2, link.serverIPv6)

					doResp := &bytes.Buffer{}
					doResp.Write(ppp)
					doResp.Write(pppIPv6CP)
					//
					doResp.Write(confAck)
					doResp.WriteByte(id)
					doResp.Write(ipv6type)
					doResp.WriteByte(id2)
					doResp.Write(v6)
					doResp.Write(v)

					toF5andSend(link.conn, doResp.Bytes())

					doResp = &bytes.Buffer{}
					doResp.Write(ppp)
					doResp.Write(pppIPv6CP)
					//
					doResp.Write(confRequest)
					doResp.WriteByte(id)
					doResp.Write(ipv6type)
					doResp.WriteByte(id2)
					doResp.Write(v6)
					for i := 0; i < 8; i++ {
						doResp.WriteByte(0)
					}

					toF5andSend(link.conn, doResp.Bytes())

					return
				}
			}
		}
		if v := readBuf(v, confAck); v != nil {
			id := v[0]
			if v := readBuf(v[1:], ipv6type); v != nil {
				id2 := v[0]
				if v := readBuf(v[1:], v6); v != nil {
					link.localIPv6 = bytesToIPv6(v)
					log.Printf("id: %d, id2: %d, Local IPv6 acknowledged: %s", id, id2, link.localIPv6)

					return
				}
			}
		}
		if v := readBuf(v, confNack); v != nil {
			id := v[0]
			if v := readBuf(v[1:], ipv6type); v != nil {
				id2 := v[0]
				if v := readBuf(v[1:], v6); v != nil {
					log.Printf("id: %d, id2: %d, Local IPv6 not acknowledged: %s", id, id2, bytesToIPv6(v))

					doResp := &bytes.Buffer{}
					doResp.Write(ppp)
					doResp.Write(pppIPv6CP)
					//
					doResp.Write(confRequest)
					doResp.WriteByte(id)
					doResp.Write(ipv6type)
					doResp.WriteByte(id2)
					doResp.Write(v6)
					doResp.Write(v)

					toF5andSend(link.conn, doResp.Bytes())
					return
				}
			}
		}
	}

	// it is PPP header
	if v := readBuf(buf, ppp); v != nil {
		// it is pppLCP
		if v := readBuf(v, pppLCP); v != nil {
			if v := readBuf(v, confTermReq); v != nil {
				id := v[0]
				if v := readBuf(v[1:], terminate); v != nil {
					link.errChan <- fmt.Errorf("id: %d, Link terminated with: %s", id, v)
					return
				}
			}
			if v := readBuf(v, echoReq); v != nil {
				id := v[0]
				if debug {
					log.Printf("id: %d, echo", id)
				}
				// live pings
				doResp := &bytes.Buffer{}
				doResp.Write(ppp)
				doResp.Write(pppLCP)
				//
				doResp.Write(echoRep)
				doResp.WriteByte(id)
				doResp.Write(v[1:])

				toF5andSend(link.conn, doResp.Bytes())
				return
			}
			if v := readBuf(v, protoReject); v != nil {
				id := v[0]
				if v := readBuf(v[1:], protoRej); v != nil {
					log.Printf("id: %d, Protocol reject:\n%s", id, hex.Dump(v))
					return
				}
			}
			// it is pppLCP
			if v := readBuf(v, confRequest); v != nil {
				id := v[0]
				// configuration requested
				if v := readBuf(v[1:], mtuRequest); v != nil {
					// MTU request
					if v := readBuf(v, mtuHeader); v != nil {
						// set MTU
						t := v[:mtuSize]
						link.mtu = append(t[:0:0], t...)
						link.mtuInt = binary.BigEndian.Uint16(link.mtu)
						log.Printf("MTU: %d", link.mtuInt)
						if v := readBuf(v[mtuSize:], accm); v != nil {
							if v := readBuf(v, magicHeader); v != nil {
								magic := v[:magicSize]
								log.Printf("Magic: %x", magic)
								log.Printf("PFC: %x", v[magicSize:magicSize+len(pfc)])
								log.Printf("ACFC: %x", v[magicSize+len(pfc):])

								doResp := &bytes.Buffer{}
								doResp.Write(ppp)
								doResp.Write(pppLCP)
								//
								doResp.Write(confRequest)
								doResp.WriteByte(id)
								doResp.Write(ipv6type)
								doResp.Write(accm)
								doResp.Write(pfc)
								doResp.Write(acfc)

								toF5andSend(link.conn, doResp.Bytes())

								doResp = &bytes.Buffer{}
								doResp.Write(ppp)
								doResp.Write(pppLCP)
								//
								doResp.Write(confRej)
								//doResp.Write(confRequest)
								doResp.WriteByte(id)
								doResp.Write(ipv4type)
								doResp.Write(magicHeader)
								doResp.Write(magic)

								toF5andSend(link.conn, doResp.Bytes())

								return
							} else {
								log.Fatalf("Wrong magic header")
							}
						} else {
							log.Fatalf("Wrong ACCM")
						}
					}
				}
				if v := readBuf(v[1:], mtuResponse); v != nil {
					if v := readBuf(v, mtuHeader); v != nil {
						if v := readBuf(v, link.mtu); v != nil {
							if v := readBuf(v, accm); v != nil {
								if v := readBuf(v, pfc); v != nil {
									if v := readBuf(v, acfc); v != nil {
										log.Printf("id: %d, MTU accepted", id)

										doResp := &bytes.Buffer{}
										doResp.Write(ppp)
										doResp.Write(pppLCP)
										//
										doResp.Write(confAck)
										doResp.WriteByte(id)
										doResp.Write(mtuResponse)
										doResp.Write(mtuHeader)
										doResp.Write(link.mtu)
										doResp.WriteByte(id)
										doResp.Write(v4)
										for i := 0; i < 4; i++ {
											doResp.WriteByte(0)
										}
										doResp.Write(pfc)
										doResp.Write(acfc)

										toF5andSend(link.conn, doResp.Bytes())

										return
									}
								}
							}
						}
					}
				}
			}
			// do set
			if v := readBuf(v, confAck); v != nil {
				// required settings
				id := v[0]
				if v := readBuf(v[1:], ipv6type); v != nil {
					if v := readBuf(v, accm); v != nil {
						if v := readBuf(v, pfc); v != nil {
							if v := readBuf(v, acfc); v != nil {
								log.Printf("id: %d, IPV6 accepted", id)
								return
							}
						}
					}
				}
			}
			if v := readBuf(v, confNack); v != nil {
				id := v[0]
				if v := readBuf(v[1:], mtuRequest); v != nil {
					if v := readBuf(v, mtuHeader); v != nil {
						if v := readBuf(v, link.mtu); v != nil {
							log.Fatalf("id: %d, MTU not acknowledged:\n%s", id, hex.Dump(v))
						}
					}
				}
				if v := readBuf(v[1:], ipv4type); v != nil {
					if v := readBuf(v, magicHeader); v != nil {
						log.Fatalf("id: %d, IPv4 not acknowledged:\n%s", id, hex.Dump(v))
					}
				}
			}
		}
	}

	log.Printf("Unknown PPP data:\n%s", hex.Dump(buf))

	return
}

// Encode F5 packet
// http->tun
func (l *vpnLink) httpToTun() {
	buf := make([]byte, bufferSize)
	for {
		select {
		case <-l.termChan:
			return
		default:
			rn, err := l.conn.Read(buf)
			if err != nil {
				l.errChan <- fmt.Errorf("fatal read http: %s", err)
				return
			}
			if debug {
				log.Printf("Read %d bytes from http:\n%s", rn, hex.Dump(buf[:rn]))
			}
			err = fromF5(l, buf[:rn])
			if err != nil {
				l.errChan <- err
				return
			}
		}
	}
}

func toF5(buf []byte) ([]byte, error) {
	if len(buf) == 0 {
		return nil, fmt.Errorf("cannot encapsulate zero packet")
	}

	if buf[0] == 0x45 {
		buf = append(ipv4header, buf...)
	}

	// deal with the "Protocol reject: 46 c0"
	if buf[0] == 0x46 {
		buf = append(ipv4header, buf...)
	}

	if buf[0] == 0x60 {
		buf = append(ipv6header, buf...)
	}

	lenght := len(buf)

	tmp := bytes.NewBuffer([]byte{0xf5, 0x00})

	err := binary.Write(tmp, binary.BigEndian, uint16(lenght))
	if err != nil {
		return nil, fmt.Errorf("failed to write F5 header size: %s", err)
	}

	n, err := tmp.Write(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to F5 packet: %s", err)
	}
	if n != lenght {
		return nil, fmt.Errorf("written data length mismatch: %d != %d", n, lenght)
	}

	return tmp.Bytes(), nil
}

/*
func toF5(buf []byte) ([]byte, error) {
	lenght := len(buf)
	if lenght == 0 {
		return nil, fmt.Errorf("cannot encapsulate zero slice")
	}

	tmp := &bytes.Buffer{}
	tmp.Write([]byte{0xf5, 0x00})

	var hl uint16
	// add ipv4 header
	if buf[0] == 0x45 {
		tmp.Write(ipv4header)
		hl++
	}
	// add ipv6 header
	if buf[0] == 0x60 {
		tmp.Write(ipv6header)
		hl++
	}

	err := binary.Write(tmp, binary.BigEndian, uint16(lenght)+hl)
	if err != nil {
		return nil, fmt.Errorf("failed to write F5 header size: %s", err)
	}

	n, err := tmp.Write(buf)
	if err != nil {
		return nil, fmt.Errorf("failed to write data to F5 packet: %s", err)
	}
	if n != lenght {
		return nil, fmt.Errorf("written data length mismatch: %d != %d", n, lenght)
	}

	return tmp.Bytes(), nil
}
*/

// Decode into F5 packet
// tun->http
func (l *vpnLink) tunToHttp() {
	done := <-l.upChan
	if !done {
		log.Printf("Unexpected link state")
		return
	}
	buf := make([]byte, bufferSize)
	for {
		select {
		case <-l.termChan:
			return
		default:
			rn, err := l.iface.Read(buf)
			if err != nil {
				log.Fatalf("Fatal read tun: %s", err)
			}
			if debug {
				log.Printf("Read %d bytes from tun:\n%s", rn, hex.Dump(buf[:rn]))
				header, _ := ipv4.ParseHeader(buf)
				log.Printf("ipv4 from tun: %s", header)
			}

			data, err := toF5(buf[:rn])
			if err != nil {
				l.errChan <- err
				return
			}
			if debug {
				log.Printf("Converted data from pppd:\n%s", hex.Dump(data))
			}

			wn, err := l.conn.Write(data)
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
		// TODO: understand why it hangs here. Two channel readers?
		// wait for tun up
		if !<-l.upChan {
			l.errChan <- fmt.Errorf("unexpected tun status event")
			return
		}
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

	if !config.PPPD {
		ipRun("link", "set", "dev", l.name, "mtu", fmt.Sprintf("%d", l.mtuInt))
		ipRun("link", "set", "arp", "on", "dev", l.name)
		ipRun("link", "set", "multicast", "off", "dev", l.name)
		ipRun("addr", "add", l.localIPv4.String(), "peer", l.serverIPv4.String(), "dev", l.name)
		//ipRun("addr", "add", l.localIPv6.String(), "peer", l.serverIPv6.String(), "dev", l.name)
		ipRun("link", "set", "dev", l.name, "up")

		gw, err := gateway.DiscoverGateway()
		if err != nil {
			l.errChan <- fmt.Errorf("failed to discover the gateway: %s", err)
		}

		ipRun("route", "add", l.serverIPs[0].String(), "via", gw.String(), "proto", "unspec", "metric", "1")
	}

	for _, cidr := range config.Routes {
		if false && cidrContainsIPs(cidr, l.serverIPs) {
			log.Printf("Skipping %s subnet", cidr)
			//continue
		}
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

	if !config.PPPD {
		gw, err := gateway.DiscoverGateway()
		if err != nil {
			l.errChan <- fmt.Errorf("failed to discover the gateway: %s", err)
		}

		ipRun("route", "del", l.serverIPs[0].String(), "via", gw.String(), "proto", "unspec", "metric", "1")
	}

	if l.ret == nil && l.routesReady && l.link != nil {
		log.Printf("Removing routes from %s interface", l.name)
		for _, cidr := range config.Routes {
			if false && cidrContainsIPs(cidr, l.serverIPs) {
				log.Printf("Skipping %s subnet", cidr)
				//continue
			}
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
