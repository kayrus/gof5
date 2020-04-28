package pkg

import (
	"encoding/xml"
	"fmt"
	"net"
	"net/url"
	"strings"
)

const (
	routesConfig = "routes.yaml"
	resolvPath   = "/etc/resolv.conf"
	cookiesPath  = "cookies"
	userAgent    = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1a2pre) Gecko/2008073000 Shredder/3.0a2pre ThunderBrowse/3.2.1.8"
)

var (
	currDir string
	debug   bool
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

type Object struct {
	SessionID   string `xml:"Session_ID"`
	IpV4        bool   `xml:"IPV4_0,string"`
	IpV6        bool   `xml:"IPV6_0,string"`
	UrZ         string `xml:"ur_Z"`
	HDLCFraming string `xml:"hdlc_framing,string"`
	Host        string `xml:"host0"`
	Port        string `xml:"port0"`
	TunnelHost  string `xml:"tunnel_host0"`
	TunnelPort  string `xml:"tunnel_port0"`
	Add2Hosts   string `xml:"Add2Hosts0"`
	/*
		DNS             []net.IP       `xml:"-"`
		DNS6            []net.IP       `xml:"-"`
	*/
	DNS             []string       `xml:"-"`
	DNS6            []string       `xml:"-"`
	ExcludeSubnets  []*net.IPNet   `xml:"-"`
	ExcludeSubnets6 []*net.IPNet   `xml:"-"`
	TrafficControl  TrafficControl `xml:"-"`
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
	DNS    []string     `yaml:"dns"`
	Routes []*net.IPNet `yaml:"-"`
}

func (r *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type tmp Config
	var s struct {
		tmp
		DNS    []string `yaml:"dns"`
		Routes []string `yaml:"routes"`
	}

	err := unmarshal(&s)
	if err != nil {
		return err
	}

	*r = Config(s.tmp)
	r.DNS = s.DNS

	for _, v := range s.Routes {
		// TODO: change logic?
		if !strings.Contains(v, "/") {
			v += "/32"
		}
		_, cidr, err := net.ParseCIDR(v)
		if err != nil {
			return fmt.Errorf("Cannot parse %s CIDR: %s", v, err)
		}
		r.Routes = append(r.Routes, cidr)
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
			}
		}
		return t
	}
	return nil
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
	}

	err := d.DecodeElement(&s, &start)
	if err != nil {
		return err
	}
	*o = Object(s.tmp)

	if v, err := url.QueryUnescape(s.TrafficControl); err == nil {
		err = xml.Unmarshal([]byte(v), &o.TrafficControl)
		if err != nil {
			return err
		}
	}

	/*
		o.DNS = processIPs(s.DNS)
		o.DNS6 = processIPs(s.DNS6)
	*/
	o.DNS = strings.FieldsFunc(strings.TrimSpace(s.DNS), splitFunc)
	o.DNS6 = strings.FieldsFunc(strings.TrimSpace(s.DNS6), splitFunc)
	o.ExcludeSubnets = processCIDRs(s.ExcludeSubnets)
	o.ExcludeSubnets6 = processCIDRs(s.ExcludeSubnets6)

	return nil
}
