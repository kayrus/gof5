package client

import (
	"crypto/tls"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/kayrus/gof5/pkg/config"
	"github.com/kayrus/gof5/pkg/cookie"
	"github.com/kayrus/gof5/pkg/link"
)

type Options struct {
	config.Config
	Server        string
	Username      string
	Password      string
	SessionID     string
	CACert        string
	Cert          string
	Key           string
	CloseSession  bool
	Debug         bool
	Sel           bool
	Version       bool
	ProfileIndex  int
	Renegotiation tls.RenegotiationSupport
}

func Connect(opts *Options) error {
	if opts.Server == "" {
		fmt.Print("Enter server address: ")
		fmt.Scanln(&opts.Server)
	}

	u, err := url.Parse(opts.Server)
	if err != nil {
		return fmt.Errorf("failed to parse server hostname: %s", err)
	}
	if u.Scheme != "https" {
		u, err = url.Parse(fmt.Sprintf("https://%s", u.Host))
		if err != nil {
			return fmt.Errorf("failed to parse server hostname: %s", err)
		}
	}
	if u.Host == "" {
		u, err = url.Parse(fmt.Sprintf("https://%s", opts.Server))
		if err != nil {
			return fmt.Errorf("failed to parse server hostname: %s", err)
		}
		if u.Host == "" {
			return fmt.Errorf("failed to parse server hostname: %s", err)
		}
	}
	opts.Server = u.Host

	// read config
	cfg, err := config.ReadConfig(opts.Debug)
	if err != nil {
		return err
	}
	opts.Config = *cfg

	switch cfg.Renegotiation {
	case "RenegotiateOnceAsClient":
		opts.Renegotiation = tls.RenegotiateOnceAsClient
	case "RenegotiateFreelyAsClient":
		opts.Renegotiation = tls.RenegotiateFreelyAsClient
	case "RenegotiateNever", "":
		opts.Renegotiation = tls.RenegotiateNever
	default:
		return fmt.Errorf("unknown renegotiation value: '%s'", cfg.Renegotiation)
	}

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to create cookie jar: %s", err)
	}

	client := &http.Client{Jar: cookieJar}
	client.CheckRedirect = checkRedirect(client)

	tlsConf, err := tlsConfig(opts, cfg.InsecureTLS)
	if err != nil {
		return fmt.Errorf("failed to build TLS config: %v", err)
	}
	transport := &http.Transport{
		TLSClientConfig: tlsConf,
	}
	if opts.Debug {
		client.Transport = &RoundTripper{
			Rt:     transport,
			Logger: &logger{},
		}
	} else {
		client.Transport = transport
	}

	// when server select list has been chosen
	if opts.Sel {
		u, err = getServersList(client, opts.Server)
		if err != nil {
			return err
		}
		opts.Server = u.Host
	}

	// read cookies
	cookie.ReadCookies(client, u, cfg, opts.SessionID)

	if len(client.Jar.Cookies(u)) == 0 {
		// need to login
		if err := login(client, opts.Server, &opts.Username, &opts.Password); err != nil {
			return fmt.Errorf("failed to login: %s", err)
		}
	} else {
		log.Printf("Reusing saved HTTPS VPN session for %s", u.Host)
	}

	resp, err := getProfiles(client, opts.Server)
	if err != nil {
		return fmt.Errorf("failed to get VPN profiles: %s", err)
	}

	if resp.StatusCode == 302 {
		// need to relogin
		_, err = io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			return fmt.Errorf("failed to read response body: %s", err)
		}
		resp.Body.Close()

		if err := login(client, opts.Server, &opts.Username, &opts.Password); err != nil {
			return fmt.Errorf("failed to login: %s", err)
		}

		// new request
		resp, err = getProfiles(client, opts.Server)
		if err != nil {
			return fmt.Errorf("failed to get VPN profiles: %s", err)
		}
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("wrong response code on profiles get: %d", resp.StatusCode)
	}

	profile, err := parseProfile(resp.Body, opts.ProfileIndex)
	if err != nil {
		return fmt.Errorf("failed to parse VPN profiles: %s", err)
	}

	// read config, returned by F5
	cfg.F5Config, err = getConnectionOptions(client, opts, profile)
	if err != nil {
		return fmt.Errorf("failed to get VPN connection options: %s", err)
	}

	// save cookies
	if err := cookie.SaveCookies(client, u, cfg); err != nil {
		return fmt.Errorf("failed to save cookies: %s", err)
	}

	// close HTTPS VPN session
	// next VPN connection will require credentials to auth
	if opts.CloseSession {
		defer closeVPNSession(client, opts.Server)
	}

	// TLS
	l, err := link.InitConnection(opts.Server, cfg, tlsConf)
	if err != nil {
		return err
	}
	defer l.HTTPConn.Close()

	cmd := link.Cmd(cfg)

	termChan := make(chan os.Signal, 1)
	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM, syscall.SIGPIPE, syscall.SIGHUP)

	// set routes and DNS after the PPP/TUN is up
	go l.WaitAndConfig(cfg)

	// 1. stop ppp/pppd child at the very end
	defer l.StopPPPDChild(cmd)
	// 0. restore the config first
	defer l.RestoreConfig(cfg)

	if cfg.Driver == "pppd" {
		if runtime.GOOS == "freebsd" {
			// ppp log parser
			go l.PppLogParser()
		} else {
			/*
				// read file descriptor 3
				stderr, w, err := os.Pipe()
				cmd.ExtraFiles = []*os.File{w}
			*/
			stderr, err := cmd.StderrPipe()
			if err != nil {
				return fmt.Errorf("cannot allocate stderr pipe: %s", err)
			}
			// pppd log parser
			go l.PppdLogParser(stderr)
		}

		stdin, err := cmd.StdinPipe()
		if err != nil {
			return fmt.Errorf("cannot allocate stdin pipe: %s", err)
		}
		stdout, err := cmd.StdoutPipe()
		if err != nil {
			return fmt.Errorf("cannot allocate stdout pipe: %s", err)
		}

		err = cmd.Start()
		if err != nil {
			return fmt.Errorf("failed to start pppd: %s", err)
		}

		// catch ppp/pppd child termination
		go l.CatchPPPDTermination(cmd)

		// pppd http->tun go routine
		go l.PppdHTTPToTun(stdin)

		// pppd tun->http go routine
		go l.PppdTunToHTTP(stdout)
	} else {
		// http->tun go routine
		go l.HttpToTun()

		// tun->http go routine
		go l.TunToHTTP()
	}

	select {
	case sig := <-termChan:
		log.Printf("received %s signal, exiting", sig)
	case err = <-l.ErrChan:
		// error received
	case err = <-l.PppdErrChan:
		// ppp/pppd child error received
	}

	// notify tun readers and writes to stop
	close(l.TunDown)

	return err
}
