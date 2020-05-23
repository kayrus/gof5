package pkg

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

func readBuf(buf, sep []byte) []byte {
	n := bytes.Index(buf, sep)
	if n == 0 {
		return buf[len(sep):]
	}
	return nil
}

var (
	ppp       = []byte{0xff, 0x03}
	pppLCP    = []byte{0xc0, 0x21}
	pppIPCP   = []byte{0x80, 0x21}
	pppIPv6CP = []byte{0x80, 0x57}
	// LCP auth
	mtuRequest = []byte{0x00, 0x18}
	// Link-Discriminator
	terminate = []byte{0x00, 0x17}
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

func processPPP(link *vpnLink, buf []byte) error {
	// process ipv4 traffic
	if v := readBuf(buf, ipv4header); v != nil {
		if debug {
			log.Printf("Read parsed ipv4 %d bytes from http:\n%s", len(v), hex.Dump(v))
			header, _ := ipv4.ParseHeader(v)
			log.Printf("ipv4 from http: %s", header)
		}

		wn, err := link.iface.Write(v)
		if err != nil {
			return fmt.Errorf("fatal write to tun: %s", err)
		}
		if debug {
			log.Printf("Sent %d bytes to tun", wn)
		}
		return nil
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
			return fmt.Errorf("fatal write to tun: %s", err)
		}
		if debug {
			log.Printf("Sent %d bytes to tun", wn)
		}
		return nil
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

					err := toF5(link.conn, doResp.Bytes())
					if err != nil {
						return err
					}

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

					return toF5(link.conn, doResp.Bytes())
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

					// connection established
					link.nameChan <- link.iface.Name()
					link.upChan <- true

					return nil
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

					return toF5(link.conn, doResp.Bytes())
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

					err := toF5(link.conn, doResp.Bytes())
					if err != nil {
						return err
					}

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

					return toF5(link.conn, doResp.Bytes())
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

					return nil
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

					return toF5(link.conn, doResp.Bytes())
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
					return fmt.Errorf("id: %d, Link terminated with: %s", id, v)
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

				return toF5(link.conn, doResp.Bytes())
			}
			if v := readBuf(v, protoReject); v != nil {
				id := v[0]
				if v := readBuf(v[1:], protoRej); v != nil {
					log.Printf("id: %d, Protocol reject:\n%s", id, hex.Dump(v))
					return nil
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

								err := toF5(link.conn, doResp.Bytes())
								if err != nil {
									return err
								}

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

								return toF5(link.conn, doResp.Bytes())
							} else {
								return fmt.Errorf("wrong magic header")
							}
						} else {
							return fmt.Errorf("wrong ACCM")
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

										return toF5(link.conn, doResp.Bytes())
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
								return nil
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
							return fmt.Errorf("id: %d, MTU not acknowledged:\n%s", id, hex.Dump(v))
						}
					}
				}
				if v := readBuf(v[1:], ipv4type); v != nil {
					if v := readBuf(v, magicHeader); v != nil {
						return fmt.Errorf("id: %d, IPv4 not acknowledged:\n%s", id, hex.Dump(v))
					}
				}
			}
		}
	}

	return fmt.Errorf("unknown PPP data:\n%s", hex.Dump(buf))
}

func fromF5(link *vpnLink) error {
	// read the F5 packet header
	buf := make([]byte, 2)
	n, err := io.ReadFull(link.conn, buf)
	if err != nil {
		return fmt.Errorf("failed to read F5 packet header: %s", err)
	}
	if !(buf[0] == 0xf5 && buf[1] == 00) {
		return fmt.Errorf("incorrect F5 header: %x", buf)
	}

	// read the F5 packet size
	var pkglen uint16
	err = binary.Read(link.conn, binary.BigEndian, &pkglen)
	if err != nil {
		return fmt.Errorf("failed to read F5 packet size: %s", err)
	}

	// read the packet
	buf = make([]byte, pkglen)
	n, err = io.ReadFull(link.conn, buf)
	if err != nil {
		return fmt.Errorf("failed to read F5 packet of the %d size: %s", pkglen, err)
	}
	if n != int(pkglen) {
		return fmt.Errorf("incorrect F5 packet size: %d, expected: %d", n, pkglen)
	}

	// process the packet
	return processPPP(link, buf)
}

// Encode F5 packet
// http->tun
func (l *vpnLink) httpToTun() {
	for {
		select {
		case <-l.termChan:
			return
		default:
			err := fromF5(l)
			if err != nil {
				l.errChan <- err
				return
			}
		}
	}
}

func toF5(conn myConn, buf []byte) error {
	var dst io.ReadWriter
	buffer := true

	if buffer {
		dst = &bytes.Buffer{}
	} else {
		dst = conn
	}

	// TODO: figure out whether each Write creates an independent TCP packet
	// probably buffer is not a bad idea
	length := len(buf)
	if length == 0 {
		return fmt.Errorf("cannot encapsulate zero packet")
	}

	switch buf[0] >> 4 {
	case ipv4.Version:
		length += len(ipv4header)
	case ipv6.Version:
		length += len(ipv6header)
	}

	_, err := dst.Write([]byte{0xf5, 0x00})
	if err != nil {
		return fmt.Errorf("failed to write F5 header: %s", err)
	}
	err = binary.Write(dst, binary.BigEndian, uint16(length))
	if err != nil {
		return fmt.Errorf("failed to write F5 header size: %s", err)
	}

	switch buf[0] >> 4 {
	case ipv4.Version:
		_, err = dst.Write(ipv4header)
	case ipv6.Version:
		_, err = dst.Write(ipv6header)
	}
	if err != nil {
		return fmt.Errorf("failed to write IP header: %s", err)
	}

	if debug {
		log.Printf("Sending from pppd:\n%s", hex.Dump(buf))
	}

	if buffer {
		_, err = dst.Write(buf)
		if err != nil {
			return fmt.Errorf("fatal write to http: %s", err)
		}
		wn, err := io.Copy(conn, dst)
		if err != nil {
			return fmt.Errorf("fatal write to http: %s", err)
		}
		if debug {
			log.Printf("Sent %d bytes to http", wn)
		}
	} else {
		wn, err := dst.Write(buf)
		if err != nil {
			return fmt.Errorf("fatal write to http: %s", err)
		}
		if debug {
			log.Printf("Sent %d bytes to http", wn)
		}
	}

	return nil
}

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
				l.errChan <- fmt.Errorf("Fatal read tun: %s", err)
				return
			}
			if debug {
				log.Printf("Read %d bytes from tun:\n%s", rn, hex.Dump(buf[:rn]))
				header, _ := ipv4.ParseHeader(buf[:rn])
				log.Printf("ipv4 from tun: %s", header)
			}

			err = toF5(l.conn, buf[:rn])
			if err != nil {
				l.errChan <- err
				return
			}
		}
	}
}
