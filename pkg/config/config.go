package config

import (
	"bufio"
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/kayrus/gof5/pkg/util"

	"gopkg.in/yaml.v2"
)

const (
	ResolvPath = "/etc/resolv.conf"
	configDir  = ".gof5"
	configName = "config.yaml"
)

var (
	defaultDNSListenAddr = net.IPv4(127, 0, 0, 1).To4()
	supportedDrivers     = []string{"wireguard", "water", "pppd"}
)

func parseIP(ip string) net.IP {
	v := net.ParseIP(ip)
	if v == nil {
		return nil
	}
	if v := v.To4(); v != nil {
		return v
	} else if v := v.To16(); v != nil {
		return v
	}
	return nil
}

func parseResolvConf(cfg *Config) {
	if cfg.ResolvConf == nil {
		return
	}

	buf := bufio.NewReader(bytes.NewReader(cfg.ResolvConf))
	for line, isPrefix, err := buf.ReadLine(); err == nil && !isPrefix; line, isPrefix, err = buf.ReadLine() {
		if len(line) > 0 && (line[0] == ';' || line[0] == '#') {
			continue
		}

		f := strings.FieldsFunc(string(line), util.SplitFunc)
		if len(f) < 1 {
			continue
		}
		switch f[0] {
		case "nameserver":
			if len(f) > 1 && len(cfg.DNSServers) < 3 {
				v := parseIP(f[1])
				if v == nil {
					continue
				}
				cfg.DNSServers = append(cfg.DNSServers, v)
			}
		case "search":
			cfg.DNSSearch = append(cfg.DNSSearch, f[1:]...)
		}
	}
}

func ReadConfig(debug bool) (*Config, error) {
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
		// detect home directory
		usr, err = user.Current()
		if err != nil {
			return nil, fmt.Errorf("failed to detect home directory: %s", err)
		}
	}
	configPath := filepath.Join(usr.HomeDir, configDir)

	var uid, gid int
	// windows preserves the original user parameters, no need to detect uid/gid
	if runtime.GOOS != "windows" {
		uid, err = strconv.Atoi(usr.Uid)
		if err != nil {
			return nil, fmt.Errorf("failed to convert %q UID to integer: %s", usr.Uid, err)
		}
		gid, err = strconv.Atoi(usr.Gid)
		if err != nil {
			return nil, fmt.Errorf("failed to convert %q GID to integer: %s", usr.Uid, err)
		}
	}

	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		log.Printf("%q directory doesn't exist, creating...", configPath)
		if err := os.Mkdir(configPath, 0700); err != nil {
			return nil, fmt.Errorf("failed to create %q config directory: %s", configPath, err)
		}
		// windows preserves the original user parameters, no need to chown
		if runtime.GOOS != "windows" {
			if err := os.Chown(configPath, uid, gid); err != nil {
				return nil, fmt.Errorf("failed to set an owner for the %q config directory: %s", configPath, err)
			}
		}
	}

	cfg := &Config{}
	// read config file
	// if config doesn't exist, use defaults
	if raw, err := ioutil.ReadFile(filepath.Join(configPath, configName)); err == nil {
		if err = yaml.Unmarshal(raw, cfg); err != nil {
			return nil, fmt.Errorf("cannot parse %s file: %v", configName, err)
		}
	} else {
		log.Printf("Cannot read config file: %s", err)
	}

	// set default driver
	if cfg.Driver == "" {
		cfg.Driver = "wireguard"
	}

	if cfg.Driver == "wireguard" {
		if err := checkWinTunDriver(); err != nil {
			return nil, err
		}
	}

	if cfg.Driver == "pppd" && runtime.GOOS == "windows" {
		return nil, fmt.Errorf("pppd driver is not supported in Windows")
	}

	if !util.StrSliceContains(supportedDrivers, cfg.Driver) {
		return nil, fmt.Errorf("%q driver is unsupported, supported drivers are: %q", cfg.Driver, supportedDrivers)
	}

	if !cfg.DisableDNS {
		// read current resolv.conf
		cfg.ResolvConf, err = ioutil.ReadFile(ResolvPath)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("cannot read %s: %s", ResolvPath, err)
		}
	}

	if len(cfg.DNSServers) == 0 {
		if runtime.GOOS == "windows" {
			// detect current DNS servers
			args := []string{
				"-Command",
				"Get-DnsClientServerAddress -AddressFamily ipv4 | Select-Object -ExpandProperty ServerAddresses",
			}
			out, err := exec.Command("powershell.exe", args...).Output()
			if err != nil {
				return nil, fmt.Errorf("failed to detect current DNS servers: %v", err)
			}
			for _, v := range strings.FieldsFunc(string(out), util.SplitFunc) {
				v := parseIP(v)
				if v == nil {
					continue
				}
				cfg.DNSServers = append(cfg.DNSServers, v)
			}
		} else {
			parseResolvConf(cfg)
		}
	}

	if cfg.ListenDNS == nil {
		cfg.ListenDNS = defaultDNSListenAddr
	}

	cfg.Path = configPath
	cfg.Uid = uid
	cfg.Gid = gid

	cfg.Debug = debug

	return cfg, nil
}
