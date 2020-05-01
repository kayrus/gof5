package pkg

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/creack/pty"
)

const (
	userAgent    = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1a2pre) Gecko/2008073000 Shredder/3.0a2pre ThunderBrowse/3.2.1.8"
	userAgentVPN = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0; F5 Networks Client)"
)

func checkRedirect(c *http.Client) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if req.URL.Path == "/my.logout.php3" || req.URL.Query().Get("errorcode") != "" {
			// clear cookies
			var err error
			c.Jar, err = cookiejar.New(nil)
			if err != nil {
				return fmt.Errorf("failed to create cookie jar: %s", err)
			}
			return http.ErrUseLastResponse
		}
		return nil
	}
}

func login(c *http.Client, server, username, password string) error {
	log.Printf("Logging in...")
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s", server), nil)
	req.Proto = "HTTP/1.0"
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	data := url.Values{}
	data.Set("username", username)
	data.Add("password", password)
	data.Add("vhost", "standard")
	req, err = http.NewRequest("POST", fmt.Sprintf("https://%s/my.policy?outform=xml", server), strings.NewReader(data.Encode()))
	req.Header.Set("Referer", fmt.Sprintf("https://%s/my.policy", server))
	req.Header.Set("User-Agent", userAgent)
	resp, err = c.Do(req)
	if err != nil {
		return err
	}
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	/*
		if resp.StatusCode == 302 && resp.Header.Get("Location") == "/my.policy" {
			return nil
		}
	*/

	// TODO: parse response 302 location and error code
	if resp.StatusCode == 302 || bytes.Contains(body, []byte("Session Expired/Timeout")) {
		return fmt.Errorf("wrong credentials")
	}

	return nil
}

func parseProfile(body []byte) (string, error) {
	var profiles Profiles
	if err := xml.Unmarshal(body, &profiles); err != nil {
		return "", fmt.Errorf("failed to unmarshal a response: %s", err)
	}

	if profiles.Type == "VPN" {
		for _, v := range profiles.Favorites {
			return v.Params, nil
		}
	}

	return "", fmt.Errorf("VPN profile was not found")
}

func getProfiles(c *http.Client, server string) (*http.Response, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/vdesk/vpn/index.php3?outform=xml&client_version=2.0", server), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build a request: %s", err)
	}
	req.Header.Set("User-Agent", userAgent)
	return c.Do(req)
}

func getConnectionOptions(c *http.Client, server string, profile string) (*Favorite, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/vdesk/vpn/connect.php3?%s&outform=xml&client_version=2.0", server, profile), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build a request: %s", err)
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to read a request: %s", err)
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read a response: %s", err)
	}
	resp.Body.Close()

	// parse profile
	var favorite Favorite
	if err = xml.Unmarshal(body, &favorite); err != nil {
		return nil, fmt.Errorf("failed to unmarshal a response: %s", err)
	}

	return &favorite, nil
}

func closeVPNSession(c *http.Client, server string) {
	// close session
	r, err := http.NewRequest("GET", fmt.Sprintf("https://%s/vdesk/hangup.php3?hangup_error=1", server), nil)
	if err != nil {
		log.Printf("Failed to close the VPN session %s", err)
	}
	defer c.Do(r)
}

func Connect(server, username, password string, closeSession bool) error {
	u, err := url.Parse(fmt.Sprintf("https://%s", server))
	if err != nil {
		return fmt.Errorf("failed to parse server hostname: %s", err)
	}

	// read config
	config, err := readConfig()
	if err != nil {
		return err
	}

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to create cookie jar: %s", err)
	}

	client := &http.Client{Jar: cookieJar}
	client.CheckRedirect = checkRedirect(client)

	if debug {
		client.Transport = &RoundTripper{
			Rt:     &http.Transport{},
			Logger: &logger{},
		}
	}

	// read cookies
	readCookies(client, u, config)

	if len(client.Jar.Cookies(u)) == 0 {
		// need to login
		if err := login(client, server, username, password); err != nil {
			return fmt.Errorf("failed to login: %s", err)
		}
	} else {
		log.Printf("Reusing saved HTTPS VPN session for %s", u.Host)
	}

	resp, err := getProfiles(client, server)
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

		if err := login(client, server, username, password); err != nil {
			return fmt.Errorf("failed to login: %s", err)
		}

		// new request
		resp, err = getProfiles(client, server)
		if err != nil {
			return fmt.Errorf("failed to get VPN profiles: %s", err)
		}
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read VPN profiles: %s", err)
	}
	resp.Body.Close()

	profile, err := parseProfile(body)
	if err != nil {
		return fmt.Errorf("failed to parse VPN profiles: %s", err)
	}

	favorite, err := getConnectionOptions(client, server, profile)
	if err != nil {
		return fmt.Errorf("failed to get VPN connection options: %s", err)
	}

	//log.Printf("Connection options: %+#v", *favorite)

	// save cookies
	if err := saveCookies(client, u, config); err != nil {
		return fmt.Errorf("failed to save cookies: %s", err)
	}

	// TLS
	conn, err := initConnection(server, config, favorite)
	if err != nil {
		return err
	}
	defer conn.Close()

	// VPN
	if favorite.Object.IPv6 {
		config.PPPdArgs = append(config.PPPdArgs,
			"ipv6cp-accept-local",
			"ipv6cp-accept-remote",
			"+ipv6",
		)
	} else {
		config.PPPdArgs = append(config.PPPdArgs,
			// TODO: clarify why it doesn't work
			"noipv6", // Unsupported protocol 'IPv6 Control Protocol' (0x8057) received
		)
	}
	if debug {
		config.PPPdArgs = append(config.PPPdArgs,
			"debug",
			"kdebug", "1",
		)
		log.Printf("pppd args: %q", config.PPPdArgs)
	}
	cmd := exec.Command("pppd", config.PPPdArgs...)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("cannot allocate stderr pipe: %s", err)
	}

	// define link channels
	link := &vpnLink{
		errChan:  make(chan error, 1),
		upChan:   make(chan bool, 1),
		nameChan: make(chan string, 1),
		termChan: make(chan os.Signal, 1),
	}

	// error handler
	go link.errorHandler()

	// pppd log parser
	go link.pppdLogParser(stderr)

	// set routes and DNS
	go link.waitAndConfig(config, favorite)

	pppd, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("failed to start pppd: %s", err)
	}

	// terminate on pppd termination
	go link.pppdWait(cmd)

	if config.HDLC {
		// http->tun go routine
		go link.httpToTun(conn, pppd)

		// tun->http go routine
		go link.tunToHttp(conn, pppd)
	} else {
		// http->tun go routine
		go link.hdlcHttpToTun(conn, pppd)

		// tun->http go routine
		go link.hdlcTunToHttp(conn, pppd)
	}

	signal.Notify(link.termChan, syscall.SIGINT, syscall.SIGTERM)
	<-link.termChan

	link.restoreConfig(config)

	// TODO: properly wait for pppd process on ctrl+c
	cmd.Wait()

	// close HTTPS VPN session
	// next VPN connection will require credentials to auth
	if closeSession {
		closeVPNSession(client, server)
	}

	return link.ret
}
