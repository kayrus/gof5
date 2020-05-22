package pkg

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
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
	"os/signal"
	"regexp"
	"runtime"
	"strings"
	"syscall"

	"github.com/creack/pty"
	"github.com/howeyc/gopass"
	"github.com/manifoldco/promptui"
)

const (
	userAgent        = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1a2pre) Gecko/2008073000 Shredder/3.0a2pre ThunderBrowse/3.2.1.8"
	userAgentVPN     = "Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0; F5 Networks Client)"
	androidUserAgent = "Mozilla/5.0 (Linux; Android 10; SM-G975F Build/QP1A.190711.020) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.138 Mobile Safari/537.36 EdgeClient/3.0.7 F5Access/3.0.7"
)

func checkRedirect(c *http.Client) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if req.URL.Path == "/my.logout.php3" || req.URL.Path == "/vdesk/hangup.php3" || req.URL.Query().Get("errorcode") != "" {
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

func generateClientData(cData clientData) (string, error) {
	info := agentInfo{
		Type:       "standalone",
		Version:    "2.0",
		Platform:   "Linux",
		CPU:        "x64",
		LandingURI: "/",
		Hostname:   "test",
	}

	log.Printf(cData.Token)

	data, err := xml.Marshal(info)
	if err != nil {
		return "", fmt.Errorf("failed to marshal agent info: %s", err)
	}

	if info.AppID == "" {
		// put appid to the end, when it is empty
		r := regexp.MustCompile("></agent_info>")
		data = []byte(r.ReplaceAllString(string(data), "><app_id></app_id></agent_info>"))
	}

	// signature must be this, when token is "1"
	t := "4sY+pQd3zrQ5c2Fl5BwkBg=="

	values := &bytes.Buffer{}
	values.WriteString("session=&")
	values.WriteString("device_info=" + base64.StdEncoding.EncodeToString(data) + "&")
	values.WriteString("agent_result=&")
	values.WriteString("token=" + cData.Token)

	// TODO: figure out how to calculate signature
	// signature is calculated using cData.Token and UserAgent as a secret key
	// 16 bytes, most probably HMAC-MD5
	hmacMd5 := hmac.New(md5.New, []byte(cData.Token))

	// write XML into HMAC calc
	hmacMd5.Write(values.Bytes())
	sig := hmacMd5.Sum(nil)

	log.Printf("HMAC of the values: %x", sig)

	hmacMd5 = hmac.New(md5.New, []byte(cData.Token))

	// write XML into HMAC calc
	hmacMd5.Write(data)
	sig = hmacMd5.Sum(nil)
	log.Printf("HMAC of the data: %x", sig)

	log.Printf("Simple hash of the values: %x", md5.Sum(values.Bytes()))
	log.Printf("Simple hash of the data: %x", md5.Sum(data))

	//hmacMd5.Write([]byte(base64.StdEncoding.EncodeToString(data)))

	s, _ := base64.StdEncoding.DecodeString(t)
	expected := hex.EncodeToString(s)

	if v := hex.EncodeToString(sig); v != expected {
		log.Printf("Signature %q doesn't correspond to %q", v, expected)
	}

	// Uncomment this to pass the test
	//values.WriteString("signature=" + t)
	values.WriteString("&signature=" + base64.StdEncoding.EncodeToString(sig))

	clientData := base64.StdEncoding.EncodeToString(values.Bytes())

	return clientData, nil
}

func loginSignature(c *http.Client, server string, _, _ *string) error {
	log.Printf("Logging in...")
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/my.logon.php3?outform=xml&client_version=2.0&get_token=1", server), nil)
	if err != nil {
		return err
	}
	req.Proto = "HTTP/1.0"
	req.Header.Set("User-Agent", androidUserAgent)
	resp, err := c.Do(req)
	if err != nil {
		return err
	}

	var cData clientData
	dec := xml.NewDecoder(resp.Body)
	err = dec.Decode(&cData)
	resp.Body.Close()
	if err != nil {
		return err
	}

	clientData, err := generateClientData(cData)
	if err != nil {
		return err
	}

	req, err = http.NewRequest("POST", fmt.Sprintf("https://%s%s", server, cData.RedirectURL), strings.NewReader("client_data="+clientData))
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", androidUserAgent)
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Origin", "null")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")
	req.Header.Set("content-type", "application/x-www-form-urlencoded")
	req.Header.Set("X-Requested-With", "com.f5.edge.client_ics")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Accept-Encoding", "gzip, deflate")
	req.Header.Set("Accept-Language", "en-US;q=0.9,en;q=0.8")

	resp, err = c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode == 302 {
		return fmt.Errorf("Login failed")
	}

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func login(c *http.Client, server string, username, password *string) error {
	if *username == "" {
		fmt.Print("Username: ")
		fmt.Scanln(username)
	}
	if *password == "" {
		fmt.Print("Password: ")
		v, err := gopass.GetPasswd()
		if err != nil {
			return fmt.Errorf("failed to read password: %s", err)
		}
		*password = string(v)
	}

	log.Printf("Logging in...")
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s", server), nil)
	if err != nil {
		return err
	}
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
	data.Set("username", *username)
	data.Add("password", *password)
	data.Add("vhost", "standard")
	req, err = http.NewRequest("POST", fmt.Sprintf("https://%s/my.policy?outform=xml", server), strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
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
	if resp.StatusCode == 302 || bytes.Contains(body, []byte("Session Expired/Timeout")) || bytes.Contains(body, []byte("The username or password is not correct")) {
		return fmt.Errorf("wrong credentials")
	}

	return nil
}

func parseProfile(reader io.ReadCloser) (string, error) {
	var profiles Profiles
	dec := xml.NewDecoder(reader)
	err := dec.Decode(&profiles)
	reader.Close()
	if err != nil {
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

	// parse profile
	var favorite Favorite
	dec := xml.NewDecoder(resp.Body)
	err = dec.Decode(&favorite)
	resp.Body.Close()
	if err != nil {
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

func getServersList(c *http.Client, server string) (*url.URL, error) {
	r, err := http.NewRequest("GET", fmt.Sprintf("https://%s/pre/config.php", server), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create a request to get servers list: %s", err)
	}
	resp, err := c.Do(r)
	if err != nil {
		return nil, fmt.Errorf("failed to request servers list: %s", err)
	}

	var s preConfigProfile
	dec := xml.NewDecoder(resp.Body)
	err = dec.Decode(&s)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal servers list: %s", err)
	}

	prompt := promptui.Select{
		Label: "Select Server",
		Items: s.Servers,
	}

	i, _, err := prompt.Run()
	if err != nil {
		return nil, fmt.Errorf("prompt failed: %s", err)
	}

	u, err := url.Parse(s.Servers[i].Address)
	if err != nil {
		return nil, fmt.Errorf("failed to parse server hostname: %s", err)
	}

	return u, nil
}

func Connect(server, username, password string, closeSession, sel bool) error {
	u, err := url.Parse(fmt.Sprintf("%s", server))
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
		u, err = url.Parse(fmt.Sprintf("https://%s", server))
		if err != nil {
			return fmt.Errorf("failed to parse server hostname: %s", err)
		}
		if u.Host == "" {
			return fmt.Errorf("failed to parse server hostname: %s", err)
		}
	}
	server = u.Host

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
			Rt: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.InsecureTLS},
			},
			Logger: &logger{},
		}
	} else {
		client.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: config.InsecureTLS},
		}
	}

	// when server select list has been chosen
	if sel {
		u, err = getServersList(client, server)
		if err != nil {
			return err
		}
		server = u.Host
	}

	// read cookies
	readCookies(client, u, config)

	if len(client.Jar.Cookies(u)) == 0 {
		// need to login
		if err := login(client, server, &username, &password); err != nil {
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

		if err := login(client, server, &username, &password); err != nil {
			return fmt.Errorf("failed to login: %s", err)
		}

		// new request
		resp, err = getProfiles(client, server)
		if err != nil {
			return fmt.Errorf("failed to get VPN profiles: %s", err)
		}
	}

	if resp.StatusCode != 200 {
		return fmt.Errorf("wrong response code on profiles get: %d", resp.StatusCode)
	}

	profile, err := parseProfile(resp.Body)
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
	link, err := initConnection(server, config, favorite)
	if err != nil {
		return err
	}
	defer link.conn.Close()

	var cmd *exec.Cmd
	if config.PPPD {
		// VPN
		if config.IPv6 && bool(favorite.Object.IPv6) {
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

		switch runtime.GOOS {
		default:
			cmd = exec.Command("pppd", config.PPPdArgs...)
		case "freebsd":
			cmd = exec.Command("ppp", "-direct")
		}
	}

	// error handler
	go link.errorHandler()

	// set routes and DNS
	go link.waitAndConfig(config, favorite)

	if config.PPPD {
		if runtime.GOOS == "freebsd" {
			// pppd log parser
			go link.pppLogParser()
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
			go link.pppdLogParser(stderr)
		}

		pppd, err := pty.Start(cmd)
		if err != nil {
			return fmt.Errorf("failed to start pppd: %s", err)
		}

		// terminate on pppd termination
		go link.pppdWait(cmd)

		// pppd http->tun go routine
		go link.pppdHttpToTun(pppd)

		// pppd tun->http go routine
		go link.pppdTunToHttp(pppd)
	} else {
		// http->tun go routine
		go link.httpToTun()

		// tun->http go routine
		go link.tunToHttp()
	}

	signal.Notify(link.termChan, syscall.SIGINT, syscall.SIGTERM)
	<-link.termChan

	link.restoreConfig(config)

	if config.PPPD {
		// TODO: properly wait for pppd process on ctrl+c
		cmd.Wait()
	}

	// close HTTPS VPN session
	// next VPN connection will require credentials to auth
	if closeSession {
		closeVPNSession(client, server)
	}

	return link.ret
}
