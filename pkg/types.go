package pkg

import (
	"encoding/xml"
	"fmt"
	"log"
	"net"
	"net/url"
	"os/user"
	"strings"
)

var (
	debug bool
)

func SetDebug(d bool) {
	debug = d
}

type Session struct {
	Token         string `xml:"token"`
	Version       string `xml:"version"`
	RedirectURL   string `xml:"redirect_url"`
	MaxClientData string `xml:"max_client_data"`
}

// Profiles list
type Profiles struct {
	Type      string         `xml:"type,attr"`
	Limited   string         `xml:"limited,attr"`
	Favorites []FavoriteItem `xml:"favorite"`
}

type FavoriteItem struct {
	ID      string `xml:"id,attr"`
	Caption string `xml:"caption"`
	Name    string `xml:"name"`
	Params  string `xml:"params"`
}

// Options
type Favorite struct {
	Object Object `xml:"object"`
}

type Bool bool

type Object struct {
	SessionID                      string         `xml:"Session_ID"`
	IPv4                           Bool           `xml:"IPV4_0,string"`
	IPv6                           Bool           `xml:"IPV6_0,string"`
	UrZ                            string         `xml:"ur_Z"`
	HDLCFraming                    Bool           `xml:"-"`
	Host                           string         `xml:"host0"`
	Port                           string         `xml:"port0"`
	TunnelHost                     string         `xml:"tunnel_host0"`
	TunnelPort                     string         `xml:"tunnel_port0"`
	Add2Hosts                      string         `xml:"Add2Hosts0"`
	DNSSuffix                      string         `xml:"DNSSuffix0"`
	DNSRegisterConnection          int            `xml:"DNSRegisterConnection0"`
	DNSUseDNSSuffixForRegistration int            `xml:"DNSUseDNSSuffixForRegistration0"`
	SplitTunneling                 int            `xml:"SplitTunneling0"`
	DNSSPlit                       string         `xml:"DNS_SPLIT0"`
	TunnelDTLS                     bool           `xml:"tunnel_dtls,string"`
	TunnelPortDTLS                 string         `xml:"tunnel_port_dtls,string"`
	AllowLocalSubnetAccess         bool           `xml:"AllowLocalSubnetAccess0,string"`
	AllowLocalDNSServersAccess     bool           `xml:"AllowLocalDNSServersAccess0,string"`
	AllowLocalDHCPAccess           bool           `xml:"AllowLocalDHCPAccess0,string"`
	DNS                            []net.IP       `xml:"-"`
	DNS6                           []net.IP       `xml:"-"`
	ExcludeSubnets                 []*net.IPNet   `xml:"-"`
	ExcludeSubnets6                []*net.IPNet   `xml:"-"`
	TrafficControl                 TrafficControl `xml:"-"`
}

type TrafficControl struct {
	Flow []Flow `xml:"flow"`
}

type Flow struct {
	Name    string `xml:"name,attr"`
	Rate    string `xml:"rate,attr"`
	Ceiling string `xml:"ceiling,attr"`
	Mode    string `xml:"mode,attr"`
	Burst   string `xml:"burst,attr"`
	Type    string `xml:"type,attr"`
	Via     string `xml:"via,attr"`
	Filter  Filter `xml:"filter"`
}

type Filter struct {
	Proto   string `xml:"proto,attr"`
	Src     string `xml:"src,attr"`
	SrcMask string `xml:"src_mask,attr"`
	SrcPort string `xml:"src_port,attr"`
	Dst     string `xml:"dst,attr"`
	DstMask string `xml:"dst_mask,attr"`
	DstPort string `xml:"dst_port,attr"`
}

type Config struct {
	// defaults to true
	PPPD        Bool         `yaml:"pppd"`
	DNS         []string     `yaml:"dns"`
	Routes      []*net.IPNet `yaml:"-"`
	PPPdArgs    []string     `yaml:"pppdArgs"`
	InsecureTLS bool         `yaml:"insecureTLS"`
	// list of DNS local servers
	// when list is empty, parsed from /etc/resolv.conf
	DNSServers []net.IP `yaml:"-"`
	// internal parameters
	// current user or sudo user
	user *user.User
	// config path
	path string
	// current user or sudo user UID
	uid int
	// current user or sudo user GID
	gid int
	// list of DNS servers, returned by F5
	vpnServers []net.IP
}

type Cookies map[string][]string

func (b Bool) String() string {
	if b {
		return "yes"
	}
	return "no"
}

func (r *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type tmp Config
	var s struct {
		tmp
		Routes     []string `yaml:"routes"`
		DNSServers []string `yaml:"dnsServers"`
		PPPdArgs   []string `yaml:"pppdArgs"`
	}

	if err := unmarshal(&s.tmp); err != nil {
		return err
	}

	if err := unmarshal(&s); err != nil {
		return err
	}

	*r = Config(s.tmp)

	for _, v := range s.Routes {
		cidr, err := parseCIDR(v)
		if err != nil {
			return fmt.Errorf("Cannot parse %s CIDR: %s", v, err)
		}
		r.Routes = append(r.Routes, cidr)
	}

	// default pppd arguments
	r.PPPdArgs = []string{
		"logfd", "2",
		"noauth",
		"nodetach",
		//"crtscts",
		"passive",
		//"local",
		"ipcp-accept-local",
		"ipcp-accept-remote",
		"nodefaultroute",
		//"lcp-echo-interval", "1",
		//"lcp-echo-failure", "20",
		//"lcp-echo-adaptive",
		//"lcp-echo-interval", "0",
		//"defaultroute",
		// nocompression
		"novj",
		"novjccomp",
		"noaccomp",
		"noccp",
		"nopcomp",
		"nopredictor1",
		"nodeflate", // Protocol-Reject for 'Compression Control Protocol' (0x80fd) received
		"nobsdcomp", // Protocol-Reject for 'Compression Control Protocol' (0x80fd) received
	}
	if len(s.PPPdArgs) > 0 {
		// extra pppd args
		r.PPPdArgs = append(r.PPPdArgs, s.PPPdArgs...)
	}

	r.DNSServers = make([]net.IP, len(s.DNSServers))
	for i, v := range s.DNSServers {
		r.DNSServers[i] = net.ParseIP(v)
	}

	return nil
}

func splitFunc(c rune) bool {
	return c == ' '
}

func processIPs(ips string) []net.IP {
	if v := strings.FieldsFunc(strings.TrimSpace(ips), splitFunc); len(v) > 0 {
		var t = make([]net.IP, len(v))
		for i, v := range v {
			t[i] = net.ParseIP(v)
		}
		return t
	}
	return nil
}

func processCIDRs(cidrs string) []*net.IPNet {
	if v := strings.FieldsFunc(strings.TrimSpace(cidrs), splitFunc); len(v) > 0 {
		var t []*net.IPNet
		for _, v := range v {
			if v := strings.Split(v, "/"); len(v) == 2 {
				t = append(t, &net.IPNet{
					IP:   net.ParseIP(v[0]),
					Mask: net.IPMask(net.ParseIP(v[1])),
				})
				continue
			}
			log.Printf("Cannot parse %q CIDR", v)
		}
		return t
	}
	return nil
}

func parseCIDR(s string) (*net.IPNet, error) {
	_, cidr, err := net.ParseCIDR(s)
	if err != nil {
		// fallback to a single IP
		ip := net.ParseIP(s)
		if ip != nil {
			return &net.IPNet{IP: ip, Mask: net.CIDRMask(32, 32)}, nil
		}
		return nil, fmt.Errorf("Cannot parse %s CIDR: %s", s, err)
	}
	return cidr, nil
}

func (o *Object) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type tmp Object
	var s struct {
		tmp
		DNS             string `xml:"DNS0"`
		DNS6            string `xml:"DNS6_0"`
		ExcludeSubnets  string `xml:"ExcludeSubnets0"`
		ExcludeSubnets6 string `xml:"ExcludeSubnets6_0"`
		TrafficControl  string `xml:"TrafficControl0"`
		HDLCFraming     string `xml:"hdlc_framing"`
	}

	if err := d.DecodeElement(&s, &start); err != nil {
		return err
	}
	*o = Object(s.tmp)

	if v, err := url.QueryUnescape(s.TrafficControl); err == nil && v != "" {
		if err = xml.Unmarshal([]byte(v), &o.TrafficControl); err != nil {
			return err
		}
	}

	o.DNS = processIPs(s.DNS)
	o.DNS6 = processIPs(s.DNS6)
	o.ExcludeSubnets = processCIDRs(s.ExcludeSubnets)
	o.ExcludeSubnets6 = processCIDRs(s.ExcludeSubnets6)

	switch v := strings.ToLower(s.HDLCFraming); v {
	case "yes":
		o.HDLCFraming = true
	case "no":
		o.HDLCFraming = false
	default:
		return fmt.Errorf("cannot parse boolean: %s", v)
	}

	return nil
}
