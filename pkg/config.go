package pkg

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path"
	"strconv"
	"strings"

	"gopkg.in/yaml.v2"
)

const (
	resolvPath  = "/etc/resolv.conf"
	configDir   = ".gof5"
	configName  = "config.yaml"
	cookiesName = "cookies.yaml"
)

func parseCookies(config *Config) Cookies {
	cookies := make(Cookies)

	v, err := ioutil.ReadFile(path.Join(config.path, cookiesName))
	if err != nil {
		log.Printf("Cannot read cookies file: %v", err)
		return cookies
	}

	if err = yaml.Unmarshal(v, &cookies); err != nil {
		log.Printf("Cannot parse cookies: %v", err)
	}

	return cookies
}

func readCookies(c *http.Client, u *url.URL, config *Config) {
	v := parseCookies(config)
	if v, ok := v[u.Host]; ok {
		var cookies []*http.Cookie
		for _, c := range v {
			if v := strings.Split(c, "="); len(v) == 2 {
				cookies = append(cookies, &http.Cookie{Name: v[0], Value: v[1]})
			}
		}
		c.Jar.SetCookies(u, cookies)
	}
}

func saveCookies(c *http.Client, u *url.URL, config *Config) error {
	raw := parseCookies(config)
	// empty current cookies list
	raw[u.Host] = nil
	// write down new cookies
	for _, c := range c.Jar.Cookies(u) {
		raw[u.Host] = append(raw[u.Host], c.String())
	}

	cookies, err := yaml.Marshal(&raw)
	if err != nil {
		return fmt.Errorf("cannot marshal cookies: %v", err)
	}

	cookiesPath := path.Join(config.path, cookiesName)
	if err = ioutil.WriteFile(cookiesPath, cookies, 0600); err != nil {
		return fmt.Errorf("failed to save cookies: %s", err)
	}

	if err = os.Chown(cookiesPath, config.uid, config.gid); err != nil {
		return fmt.Errorf("failed to set an owner for cookies file: %s", err)
	}

	return nil
}

func readConfig() (*Config, error) {
	var err error
	var usr *user.User

	// resolve sudo user ID
	if id, sudoUID := os.Geteuid(), os.Getenv("SUDO_UID"); id == 0 && sudoUID != "" {
		usr, err = user.LookupId(sudoUID)
		if err != nil {
			log.Printf("failed to lookup user ID: %s", err)
			if sudoUser := os.Getenv("SUDO_USER"); sudoUser != "" {
				usr, err = user.Lookup(sudoUser)
				if err != nil {
					return nil, fmt.Errorf("failed to lookup user name: %s", err)
				}
			}
		}
	} else {
		// detect dome directory
		usr, err = user.Current()
		if err != nil {
			return nil, fmt.Errorf("failed to detect home directory: %s", err)
		}
	}
	configPath := path.Join(usr.HomeDir, configDir)

	uid, err := strconv.Atoi(usr.Uid)
	if err != nil {
		return nil, fmt.Errorf("failed to convert %q UID to integer: %s", usr.Uid, err)
	}

	gid, err := strconv.Atoi(usr.Gid)
	if err != nil {
		return nil, fmt.Errorf("failed to convert %q GID to integer: %s", usr.Gid, err)
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Printf("%q directory doesn't exist, creating...", configPath)
		if err := os.Mkdir(configPath, 0700); err != nil {
			return nil, fmt.Errorf("failed to create %q config directory: %s", configPath, err)
		}
		if err := os.Chown(configPath, uid, gid); err != nil {
			return nil, fmt.Errorf("failed to set an owner for the %q config directory: %s", configPath, err)
		}
	}

	// read config file
	raw, err := ioutil.ReadFile(path.Join(configPath, configName))
	if err != nil {
		return nil, fmt.Errorf("cannot read %s config: %s", configName, err)
	}

	var config Config
	if err = yaml.Unmarshal(raw, &config); err != nil {
		return nil, fmt.Errorf("cannot parse %s file: %v", configName, err)
	}

	config.path = configPath
	config.user = usr
	config.uid = uid
	config.gid = gid

	return &config, nil
}
