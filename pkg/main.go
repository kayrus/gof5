package pkg

import (
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os/exec"
	"strings"

	"github.com/songgao/water"
	"golang.org/x/net/ipv4"
)

func login(c *http.Client, server, username, password string) error {
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
	req, err = http.NewRequest("POST", fmt.Sprintf("https://%s/my.policy", server), strings.NewReader(data.Encode()))
	req.Header.Set("Referer", fmt.Sprintf("https://%s/my.policy", server))
	req.Header.Set("User-Agent", userAgent)
	resp, err = c.Do(req)
	if err != nil {
		return err
	}
	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	return err
}

func readCookies(c *http.Client, u *url.URL) {
	v, err := ioutil.ReadFile(cookiesPath)
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
	return ioutil.WriteFile(cookiesPath, []byte(strings.Join(cookies, "\n")), 0644)
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

func ipRun(args ...string) {
	err := exec.Command("/sbin/ip", args...).Run()
	if nil != err {
		log.Fatalf("Error running /sbin/ip: %s", err)
	}
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

func Connect(server, username, password string, debug bool) error {
	u, err := url.Parse(fmt.Sprintf("https://%s", server))
	if err != nil {
		return err
	}

	cookieJar, err := cookiejar.New(nil)
	if err != nil {
		return err
	}

	c := &http.Client{Jar: cookieJar}
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Path == "/my.logout.php3" || req.URL.Query().Get("errorcode") != "" {
			// clear cookies
			var err error
			c.Jar, err = cookiejar.New(nil)
			if err != nil {
				return err
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
			return err
		}
	}

	resp, err := getProfiles(c, server)
	if err != nil {
		return err
	}

	if resp.StatusCode == 302 {
		// need to relogin
		_, err = io.Copy(ioutil.Discard, resp.Body)
		if err != nil {
			return err
		}
		resp.Body.Close()

		if err := login(c, server, username, password); err != nil {
			return err
		}

		// new request
		resp, err = getProfiles(c, server)
		if err != nil {
			return err
		}
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body.Close()

	profile, err := parseProfile(body)
	if err != nil {
		return err
	}

	favorite, err := getConnectionOptions(c, server, profile)
	if err != nil {
		return err
	}

	//log.Printf("Connection options: %+#v", *favorite)

	// save cookies
	if err := saveCookies(c, u); err != nil {
		return err
	}

	// TLS
	//purl, err := url.Parse(fmt.Sprintf("https://%s/myvpn?sess=%s&Z=%s&ipv4=yes&hdlc_framing=no", server, favorite.Object.SessionID, favorite.Object.UrZ))
	hostname := base64.StdEncoding.EncodeToString([]byte("my-hostname"))
	purl, err := url.Parse(fmt.Sprintf("https://%s/myvpn?sess=%s&hostname=%s&hdlc_framing=%s&ipv4=%s&ipv6=%s&Z=%s", server, favorite.Object.SessionID, hostname, favorite.Object.HDLCFraming, "yes", "yes", favorite.Object.UrZ))
	if err != nil {
		return err
	}
	conf := &tls.Config{
		InsecureSkipVerify: false,
	}

	conn, err := tls.Dial("tcp", fmt.Sprintf("%s:443", server), conf)
	if err != nil {
		return err
	}
	defer conn.Close()

	// TODO: urlencode?
	str := fmt.Sprintf("GET %s HTTP/1.0", purl.RequestURI()) + "\r\n" +
		"Host: " + server + "\r\n" +
		"\r\n"

	n, err := conn.Write([]byte(str))
	if err != nil {
		return err
	}

	log.Printf("Sent %d bytes", n)

	// TODO: http.ReadResponse()
	buf := make([]byte, 1500)
	n, err = conn.Read(buf)
	if err != nil {
		return err
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
		log.Printf("%s", v)
	}

	log.Printf("Data: %s", buf)
	log.Printf("Received %d bytes", n)

	log.Printf("Client IP: %s", clientIP)
	log.Printf("Server IP: %s", serverIP)

	// VPN
	//iface, err := taptun.NewTun("")
	config := water.Config{
		DeviceType: water.TUN,
		//PlatformSpecificParams: water.PlatformSpecificParams{MultiQueue: true},
	}

	iface, err := water.New(config)
	if err != nil {
		log.Fatal(err)
	}

	name := iface.Name()
	//name := "tun0"

	ipRun("link", "set", "dev", name, "mtu", "1332")
	ipRun("addr", "add", clientIP, "peer", serverIP, "dev", name)
	ipRun("link", "set", "dev", name, "up")
	// for test purposes redirect only to "10.0.0.0/8" CIDR
	ipRun("route", "add", "10.0.0.0/8", "via", clientIP, "proto", "unspec", "metric", "1", "dev", name)

	// http->tun go routine
	go func() {
		buf := make([]byte, 1500)
		for {
			n, err = conn.Read(buf)
			if err != nil {
				log.Fatalf("Fatal read http: %s", err)
			}
			log.Printf("Read %d bytes from http:\n%s", n, hex.Dump(buf[:n]))
			header, _ := ipv4.ParseHeader(buf[:n])
			log.Printf("ipv4 from http: %+v", header)
			n, err := iface.Write(buf[:n])
			if err != nil {
				log.Printf("Fatal write to tun: %s", err)
			}
			log.Printf("Sent %d bytes to tun", n)
		}
	}()

	// tun->http loop
	buf = make([]byte, 1500)
	for {
		n, err = iface.Read(buf)
		if err != nil {
			log.Fatalf("Fatal read tun: %s", err)
		}
		log.Printf("Read %d bytes from tun:\n%s", n, hex.Dump(buf[:n]))
		header, _ := ipv4.ParseHeader(buf[:n])
		log.Printf("ipv4 from tun: %+v", header)
		n, err := conn.Write(buf[:n])
		if err != nil {
			log.Printf("Fatal write to http: %s", err)
		}
		log.Printf("Sent %d bytes to http", n)
	}

	/*
		// close session
		req, err = http.NewRequest("GET", fmt.Sprintf("https://%s/vdesk/hangup.php3?hangup_error=1", server), nil)
		if err != nil {
			return err
		}
		defer c.Do(req)
	*/

	return nil
}
