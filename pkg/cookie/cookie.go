package cookie

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/kayrus/gof5/pkg/config"

	"gopkg.in/yaml.v2"
)

const cookiesName = "cookies.yaml"

func parseCookies(configPath string) map[string][]string {
	cookies := make(map[string][]string)

	cookiesPath := filepath.Join(configPath, cookiesName)
	v, err := ioutil.ReadFile(cookiesPath)
	if err != nil {
		// skip "no such file or directory" error on the first startup
		if e, ok := err.(*os.PathError); !ok || e.Unwrap() != syscall.ENOENT {
			log.Printf("Cannot read cookies file: %v", err)
		}
		return cookies
	}

	if err = yaml.Unmarshal(v, &cookies); err != nil {
		log.Printf("Cannot parse cookies: %v", err)
	}

	return cookies
}

func ReadCookies(c *http.Client, u *url.URL, cfg *config.Config, sessionID string) {
	v := parseCookies(cfg.Path)
	if v, ok := v[u.Host]; ok {
		var cookies []*http.Cookie
		for _, c := range v {
			if v := strings.Split(c, "="); len(v) == 2 {
				cookies = append(cookies, &http.Cookie{Name: v[0], Value: v[1]})
			}
		}
		c.Jar.SetCookies(u, cookies)
	}

	if sessionID != "" {
		log.Printf("Overriding session ID from a CLI argument")
		// override session ID from CLI parameter
		cookies := []*http.Cookie{
			{Name: "MRHSession", Value: sessionID},
		}
		c.Jar.SetCookies(u, cookies)
	}
}

func SaveCookies(c *http.Client, u *url.URL, cfg *config.Config) error {
	raw := parseCookies(cfg.Path)
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

	cookiesPath := filepath.Join(cfg.Path, cookiesName)
	if err = ioutil.WriteFile(cookiesPath, cookies, 0600); err != nil {
		return fmt.Errorf("failed to save cookies: %s", err)
	}

	if runtime.GOOS != "windows" {
		if err = os.Chown(cookiesPath, cfg.Uid, cfg.Gid); err != nil {
			return fmt.Errorf("failed to set an owner for cookies file: %s", err)
		}
	}

	return nil
}
