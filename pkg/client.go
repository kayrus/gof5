package pkg

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/hex"
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
	"path"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"github.com/vishvananda/netlink"
	"github.com/zaninime/go-hdlc"
	"gopkg.in/yaml.v2"
)

func login(c *http.Client, server, username, password string) error {
	log.Printf("Logging in...")
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s?outform=xml", server), nil)
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

	if bytes.Contains(body, []byte("Session Expired/Timeout")) {
		return fmt.Errorf("wrong credentials")
	}

	return nil
}

func readCookies(c *http.Client, u *url.URL) {
	v, err := ioutil.ReadFile(path.Join(currDir, cookiesPath))
	if err != nil {
		log.Printf("Cannot read cookies file: %v", err)
		return
	}

	var cookies []*http.Cookie
	for _, c := range strings.Split(string(v), "\n") {
		if v := strings.Split(c, "="); len(v) == 2 {
			cookies = append(cookies, &http.Cookie{Name: v[0], Value: v[1]})
		}
	}

	c.Jar.SetCookies(u, cookies)
}

func saveCookies(c *http.Client, u *url.URL) error {
	var cookies []string
	for _, c := range c.Jar.Cookies(u) {
		cookies = append(cookies, c.String())
	}
	return ioutil.WriteFile(path.Join(currDir, cookiesPath), []byte(strings.Join(cookies, "\n")), 0600)
}

func parseProfile(body []byte) (string, error) {
	var profiles Profiles
	err := xml.Unmarshal(body, &profiles)
	if err != nil {
		return "", err
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
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	return c.Do(req)
}

func getConnectionOptions(c *http.Client, server string, profile string) (*Favorite, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/vdesk/vpn/connect.php3?%s&outform=xml&client_version=2.0", server, profile), nil)
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()

	// parse profile
	var favorite Favorite
	err = xml.Unmarshal(body, &favorite)
	if err != nil {
		return nil, err
	}

	return &favorite, nil
}

func readConfig() (*Config, error) {
	// read routes file
	raw, err := ioutil.ReadFile(path.Join(currDir, routesConfig))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s config: %s", routesConfig, err)
	}

	var config Config
	err = yaml.Unmarshal(raw, &config)
	if err != nil {
		return nil, fmt.Errorf("cannot parse %s file: %v", routesConfig, err)
	}

	return &config, nil
}

// http->tun
func httpToTun(conn *tls.Conn, pppd *os.File, errChan chan error) {
	buf := make([]byte, 1500)
	for {
		rn, err := conn.Read(buf)
		if err != nil {
			errChan <- fmt.Errorf("fatal read http: %s", err)
			return
		}
		if debug {
			log.Printf("Read %d bytes from http:\n%s", rn, hex.Dump(buf[:rn]))
		}
		wn, err := pppd.Write(buf[:rn])
		if err != nil {
			errChan <- fmt.Errorf("fatal write to pppd: %s", err)
			return
		}
		if debug {
			log.Printf("Sent %d bytes to pppd", wn)
		}
	}
}

// tun->http
func tunToHttp(conn *tls.Conn, pppd *os.File, errChan chan error) {
	buf := make([]byte, 1500)
	for {
		rn, err := pppd.Read(buf)
		if err != nil {
			errChan <- fmt.Errorf("fatal read pppd: %s", err)
			return
		}
		if debug {
			log.Printf("Read %d bytes from pppd:\n%s", rn, hex.Dump(buf[:rn]))
		}
		wn, err := conn.Write(buf[:rn])
		if err != nil {
			errChan <- fmt.Errorf("fatal write to http: %s", err)
			return
		}
		if debug {
			log.Printf("Sent %d bytes to http", wn)
		}
	}
}

// Encode F5 packet into pppd HDLC format
// http->tun
func hdlcHttpToTun(conn *tls.Conn, pppd *os.File, errChan chan error) {
	buf := make([]byte, 1500)
	for {
		rn, err := conn.Read(buf)
		if err != nil {
			errChan <- fmt.Errorf("fatal read http: %s", err)
			return
		}
		if debug {
			log.Printf("Read %d bytes from http:\n%s", rn, hex.Dump(buf[:rn]))
		}
		enc := hdlc.NewEncoder(pppd)
		// TODO: parse packet header
		wn, err := enc.WriteFrame(hdlc.Encapsulate(buf[6:rn], true))
		if err != nil {
			errChan <- fmt.Errorf("fatal write to pppd: %s", err)
			return
		}
		if debug {
			log.Printf("Sent %d bytes to pppd", wn)
		}
	}
}

// Decode pppd HDLC format into F5 packet
// tun->http
func hdlcTunToHttp(conn *tls.Conn, pppd *os.File, errChan chan error) {
	for {
		dec := hdlc.NewDecoder(pppd)
		frame, err := dec.ReadFrame()
		if err != nil {
			errChan <- fmt.Errorf("fatal read pppd: %s", err)
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
			errChan <- fmt.Errorf("fatal write to http: %s", err)
			return
		}
		if debug {
			log.Printf("Sent %d bytes to http", wn)
		}
	}
}

func Connect(server, username, password string, isHdlc, closeSession bool) error {
	u, err := url.Parse(fmt.Sprintf("https://%s", server))
	if err != nil {
		return fmt.Errorf("failed to parse server hostname: %s", err)
	}

	// detect current directory
	currDir, err = os.Getwd()
	if err != nil {
		return fmt.Errorf("failed to detect current working directory: %s", err)
	}

	// read custom routes
	config, err := readConfig()
	if err != nil {
		return err
	}

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return fmt.Errorf("failed to create cookie jar: %s", err)
	}

	c := &http.Client{Jar: cookieJar}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
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

	if debug {
		c.Transport = &RoundTripper{
			Rt:     &http.Transport{},
			Logger: &logger{},
		}
	}

	// read cookies
	readCookies(c, u)
	// need login
	if len(c.Jar.Cookies(u)) == 0 {
		if err := login(c, server, username, password); err != nil {
			return fmt.Errorf("failed to login: %s", err)
		}
	} else {
		log.Printf("Reusing saved HTTPS VPN session")
	}

	resp, err := getProfiles(c, server)
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

		if err := login(c, server, username, password); err != nil {
			return fmt.Errorf("failed to login: %s", err)
		}

		// new request
		resp, err = getProfiles(c, server)
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

	favorite, err := getConnectionOptions(c, server, profile)
	if err != nil {
		return fmt.Errorf("failed to get VPN connection options: %s", err)
	}

	//log.Printf("Connection options: %+#v", *favorite)

	// save cookies
	if err := saveCookies(c, u); err != nil {
		return fmt.Errorf("failed to save cookies: %s", err)
	}

	hdlcFraming := "no"
	if isHdlc {
		hdlcFraming = "yes"
	}
	// TLS
	purl, err := url.Parse(fmt.Sprintf("https://%s/myvpn?sess=%s&Z=%s&hdlc_framing=%s", server, favorite.Object.SessionID, favorite.Object.UrZ, hdlcFraming))
	//hostname := base64.StdEncoding.EncodeToString([]byte("my-hostname"))
	//purl, err := url.Parse(fmt.Sprintf("https://%s/myvpn?sess=%s&hostname=%s&hdlc_framing=%s&ipv4=%s&ipv6=%s&Z=%s", server, favorite.Object.SessionID, hostname, favorite.Object.HDLCFraming, "yes", "no", favorite.Object.UrZ))
	if err != nil {
		return fmt.Errorf("failed to parse connection VPN: %s", err)
	}
	conf := &tls.Config{
		InsecureSkipVerify: false,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", server), conf)
	if err != nil {
		return fmt.Errorf("failed to dial %s:443: %s", server, err)
	}
	defer conn.Close()

	str := fmt.Sprintf("GET %s HTTP/1.0\r\nHost: %s\r\n\r\n", purl.RequestURI(), server)
	n, err := conn.Write([]byte(str))
	if err != nil {
		return fmt.Errorf("failed to send VPN session request: %s", err)
	}

	if debug {
		log.Printf("Sent %d bytes", n)
	}

	// TODO: http.ReadResponse()
	buf := make([]byte, 1500)
	n, err = conn.Read(buf)
	if err != nil {
		return fmt.Errorf("failed to get initial VPN connection response: %s", err)
	}

	var clientIP, serverIP string
	for _, v := range strings.Split(string(buf), "\r\n") {
		if v := strings.Split(v, ":"); len(v) == 2 {
			switch v[0] {
			case "X-VPN-client-IP":
				clientIP = v[1]
			case "X-VPN-server-IP":
				serverIP = v[1]
			}
		}
	}

	if debug {
		log.Printf("Data: %s", buf)
		log.Printf("Received %d bytes", n)

		log.Printf("Client IP: %s", clientIP)
		log.Printf("Server IP: %s", serverIP)
	}

	// VPN
	cmd := exec.Command("pppd",
		"logfd", "2",
		"noauth",
		"nodetach",
		"crtscts",
		"passive",
		"ipcp-accept-local",
		"ipcp-accept-remote",
		"local",
		"nodeflate",
		"novj",
		"nodefaultroute",
	)
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return fmt.Errorf("cannot allocate stderr pipe: %s", err)
	}

	// define channels
	errChan := make(chan error, 1)
	// error to be returned by a go routine
	var ret error
	tunUp := make(chan bool, 1)
	var name string
	tunName := make(chan string, 1)
	var link netlink.Link
	termChan := make(chan os.Signal, 1)

	// error handler
	go func() {
		ret = <-errChan
		termChan <- syscall.SIGINT
	}()

	// pppd log parser
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			if strings.Contains(scanner.Text(), "Using interface") {
				if v := strings.FieldsFunc(strings.TrimSpace(scanner.Text()), splitFunc); len(v) > 0 {
					tunName <- v[len(v)-1]
				}
			}
			if strings.Contains(scanner.Text(), "remote IP address") {
				tunUp <- true
			}
			log.Printf("\033[1;32m%s\033[0m", scanner.Text())
		}
	}()

	// restore resolv.conf on termination
	var resolvConf []byte
	var routesReady bool
	// set routes and DNS
	go func() {
		var err error
		// wait for tun name
		name = <-tunName
		if name == "" {
			errChan <- fmt.Errorf("failed to detect tunnel name")
			return
		}

		// wait for tun up
		if !<-tunUp {
			errChan <- fmt.Errorf("unexpected tun status event")
			return
		}

		// read current resolv.conf
		// reading it here in order to avoid conflicts, when the second VPN connection is established in parallel
		resolvConf, err = ioutil.ReadFile(resolvPath)
		if err != nil {
			errChan <- fmt.Errorf("cannot read %s: %s", resolvPath, err)
			return
		}

		// define DNS servers, provided by F5
		log.Printf("Setting %s", resolvPath)
		dnsSuffixes = config.DNS
		servers = favorite.Object.DNS
		var dns string
		if len(dnsSuffixes) == 0 {
			dns = "# created by gof5 VPN client" +
				"nameserver " + strings.Join(favorite.Object.DNS, "\nnameserver ") +
				"\n"
		} else {
			startDns()
			dns = fmt.Sprintf("# created by gof5 VPN client\nnameserver %s\n", listenAddr)
		}
		err = ioutil.WriteFile(resolvPath, []byte(dns), 0644)
		if err != nil {
			errChan <- fmt.Errorf("failed to write %s: %s", resolvPath, err)
			return
		}

		// set routes
		log.Printf("Setting routes on %s interface", name)
		link, err = netlink.LinkByName(name)
		if err != nil {
			errChan <- fmt.Errorf("failed to detect %s interface: %s", name, err)
			return
		}
		for _, cidr := range config.Routes {
			route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: cidr}
			if err := netlink.RouteAdd(&route); err != nil {
				errChan <- fmt.Errorf("failed to set %s route on %s interface: %s", cidr.String(), name, err)
				return
			}
		}
		routesReady = true
		log.Printf("\033[1;32m%s\033[0m", "Connection established")
	}()

	// restore original settings
	defer func() {
		if resolvConf != nil {
			log.Printf("Restoring original %s", resolvPath)
			err := ioutil.WriteFile(resolvPath, resolvConf, 0644)
			if err != nil {
				log.Printf("Failed to restore %s: %s", resolvPath, err)
			}
		}
		if routesReady && link != nil {
			log.Printf("Removing routes from %s interface", name)
			for _, cidr := range config.Routes {
				route := netlink.Route{LinkIndex: link.Attrs().Index, Dst: cidr}
				if err := netlink.RouteDel(&route); err != nil {
					log.Printf("Failed to delete %s route from %s interface: %s", cidr.String(), name, err)
				}
			}
		}
	}()

	pppd, err := pty.Start(cmd)
	if err != nil {
		return fmt.Errorf("failed to start pppd: %s", err)
	}

	// terminate on pppd termination
	go func() {
		errChan <- cmd.Wait()
	}()

	if isHdlc {
		// http->tun go routine
		go httpToTun(conn, pppd, errChan)

		// tun->http go routine
		go tunToHttp(conn, pppd, errChan)
	} else {
		// http->tun go routine
		go hdlcHttpToTun(conn, pppd, errChan)

		// tun->http go routine
		go hdlcTunToHttp(conn, pppd, errChan)
	}

	signal.Notify(termChan, syscall.SIGINT, syscall.SIGTERM)
	<-termChan

	// TODO: properly wait for pppd process on ctrl+c
	cmd.Wait()

	if closeSession {
		// close session
		r, err := http.NewRequest("GET", fmt.Sprintf("https://%s/vdesk/hangup.php3?hangup_error=1", server), nil)
		if err != nil {
			log.Printf("Failed to close the VPN session %s", err)
		}
		defer c.Do(r)
	}

	return ret
}
