package client

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
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
	"os"
	"regexp"
	"strings"

	"github.com/kayrus/gof5/pkg/config"

	"github.com/howeyc/gopass"
	"github.com/manifoldco/promptui"
	"github.com/mitchellh/go-homedir"
)

const (
	userAgent        = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1a2pre) Gecko/2008073000 Shredder/3.0a2pre ThunderBrowse/3.2.1.8"
	androidUserAgent = "Mozilla/5.0 (Linux; Android 10; SM-G975F Build/QP1A.190711.020) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/81.0.4044.138 Mobile Safari/537.36 EdgeClient/3.0.7 F5Access/3.0.7"
)

func tlsConfig(opts *Options, insecure bool) (*tls.Config, error) {
	config := &tls.Config{
		InsecureSkipVerify: insecure,
		Renegotiation:      opts.Renegotiation,
	}

	if opts.CACert != "" {
		caCert, err := readFile(opts.CACert)
		if err != nil {
			return nil, err
		}
		config.RootCAs = x509.NewCertPool()
		config.RootCAs.AppendCertsFromPEM(caCert)
	}

	if opts.Cert != "" && opts.Key != "" {
		crt, err := readFile(opts.Cert)
		if err != nil {
			return nil, err
		}
		key, err := readFile(opts.Key)
		if err != nil {
			return nil, err
		}

		cert, err := tls.X509KeyPair(crt, key)
		if err != nil {
			return nil, err
		}

		config.Certificates = []tls.Certificate{cert}
	}

	return config, nil
}

func readFile(path string) ([]byte, error) {
	if len(path) == 0 {
		return nil, nil
	}

	if path[0] == '~' {
		var err error
		path, err = homedir.Expand(path)
		if err != nil {
			return nil, err
		}
	}

	if _, err := os.Stat(path); err != nil {
		return nil, err
	}

	content, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	return bytes.TrimSpace(content), nil
}

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

func generateClientData(cData config.ClientData) (string, error) {
	info := config.AgentInfo{
		Type:       "standalone",
		Version:    "2.0",
		Platform:   "Linux",
		CPU:        "x64",
		LandingURI: "/",
		Hostname:   "test",
	}

	log.Print(cData.Token)

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

	var cData config.ClientData
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
		return fmt.Errorf("login failed")
	}

	_, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	return nil
}

func login(c *http.Client, server string, username, password *string) error {
	if *username == "" {
		fmt.Print("Enter VPN username: ")
		fmt.Scanln(username)
	}
	if *password == "" {
		fmt.Print("Enter VPN password: ")
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

func parseProfile(reader io.ReadCloser, profileIndex int, profileName string) (string, error) {
	var profiles config.Profiles
	dec := xml.NewDecoder(reader)
	err := dec.Decode(&profiles)
	reader.Close()
	if err != nil {
		return "", fmt.Errorf("failed to unmarshal a response: %s", err)
	}

	if profiles.Type == "VPN" {
		prfls := make([]string, len(profiles.Favorites))
		for i, p := range profiles.Favorites {
			if profileName != "" && profileName == p.Name {
				profileIndex = i
			}
			prfls[i] = fmt.Sprintf("%d:%s", i, p.Name)
		}
		log.Printf("Found F5 VPN profiles: %q", prfls)

		if profileIndex >= len(profiles.Favorites) {
			return "", fmt.Errorf("profile %q index is out of range", profileIndex)
		}
		log.Printf("Using %q F5 VPN profile", profiles.Favorites[profileIndex].Name)
		return profiles.Favorites[profileIndex].Params, nil
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

func getConnectionOptions(c *http.Client, opts *Options, profile string) (*config.Favorite, error) {
	req, err := http.NewRequest("GET", fmt.Sprintf("https://%s/vdesk/vpn/connect.php3?%s&outform=xml&client_version=2.0", opts.Server, profile), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to build a request: %s", err)
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)

	if err != nil {
		log.Printf("Failed to read a request: %s", err)
		log.Printf("Override link DNS values from config")
		return &config.Favorite{
			Object: config.Object{
				SessionID: opts.SessionID,
				DNS:       opts.Config.OverrideDNS,
				DNSSuffix: opts.Config.OverrideDNSSuffix,
			},
		}, nil
	}

	// parse profile
	var favorite config.Favorite
	dec := xml.NewDecoder(resp.Body)
	err = dec.Decode(&favorite)
	resp.Body.Close()
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal a response: %s", err)
	}

	// override link options
	if favorite.Object.SessionID == "" {
		favorite.Object.SessionID = opts.SessionID
	}
	if len(opts.Config.OverrideDNS) > 0 {
		favorite.Object.DNS = opts.Config.OverrideDNS
	}
	if len(opts.Config.OverrideDNSSuffix) > 0 {
		favorite.Object.DNSSuffix = opts.Config.OverrideDNSSuffix
	}

	return &favorite, nil
}

func closeVPNSession(c *http.Client, server string) {
	// close session
	r, err := http.NewRequest("GET", fmt.Sprintf("https://%s/vdesk/hangup.php3?hangup_error=1", server), nil)
	if err != nil {
		log.Printf("Failed to create a request to close the VPN session %s", err)
	}
	resp, err := c.Do(r)
	if err != nil {
		log.Printf("Failed to close the VPN session %s", err)
	}
	defer resp.Body.Close()
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

	var s config.PreConfigProfile
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

	// if scheme is not set, assume https
	if u.Scheme == "" {
		u, err = url.Parse("https://" + s.Servers[i].Address)
		if err != nil {
			return nil, fmt.Errorf("failed to parse server hostname: %s", err)
		}
	}

	return u, nil
}
