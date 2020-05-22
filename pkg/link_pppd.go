package pkg

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/hpcloud/tail"
	"github.com/zaninime/go-hdlc"
	"golang.org/x/net/ipv4"
)

// TODO: handle "fatal read pppd: read /dev/ptmx: input/output error"

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

// terminate on pppd termination
func (l *vpnLink) pppdWait(cmd *exec.Cmd) {
	err := cmd.Wait()
	if err != nil {
		l.errChan <- fmt.Errorf("pppd %s", err)
		return
	}
	l.errChan <- err
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
		// freebsd ppp
		if strings.Contains(scanner.Text(), "IPCP: myaddr") {
			l.upChan <- true
		}
		log.Printf(printGreen, scanner.Text())
	}
}

// freebsd ppp log parser
func (l *vpnLink) pppLogParser() {
	t, err := tail.TailFile("/var/log/ppp.log", tail.Config{
		Location: &tail.SeekInfo{Offset: 0, Whence: io.SeekEnd},
		Follow:   true,
		Logger:   tail.DiscardingLogger,
	})
	if err != nil {
		l.errChan <- fmt.Errorf("failed to read ppp log: %s", err)
	}
	for line := range t.Lines {
		v := strings.SplitN(line.Text, "]", 2)
		var str string
		if len(v) == 2 {
			str = strings.TrimLeft(v[1], ": ")
		}
		if strings.Contains(str, "Using interface") {
			if v := strings.FieldsFunc(strings.TrimSpace(str), splitFunc); len(v) > 0 {
				l.nameChan <- v[len(v)-1]
			}
		}
		if strings.Contains(str, "IPCP: myaddr") {
			// workaround for race condition "Network is unreachable"
			time.Sleep(time.Second)
			l.upChan <- true
		}
		log.Printf(printGreen, str)
	}
}
