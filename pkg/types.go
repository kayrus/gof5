package pkg

import (
	"encoding/base64"
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

func (b Bool) String() string {
	if b {
		return "yes"
	}
	return "no"
}

func (b Bool) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(b.String(), start)
}

func strToBool(s string) (Bool, error) {
	switch v := strings.ToLower(s); v {
	case "yes":
		return true, nil
	case "no":
		return false, nil
	}
	return false, fmt.Errorf("cannot parse boolean: %s", s)
}

type Hostname string

func (h Hostname) MarshalXML(e *xml.Encoder, start xml.StartElement) error {
	return e.EncodeElement(base64.StdEncoding.EncodeToString([]byte(h)), start)
}

// TODO: unmarshal for bool

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
	PPPD        bool         `yaml:"-"`
	ListenDNS   string       `yaml:"listenDNS"`
	DNS         []string     `yaml:"dns"`
	Routes      []*net.IPNet `yaml:"-"`
	PPPdArgs    []string     `yaml:"pppdArgs"`
	InsecureTLS bool         `yaml:"insecureTLS"`
	DTLS        bool         `yaml:"dtls"`
	IPv6        bool         `yaml:"ipv6"`
	Water       bool         `yaml:"water"`
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
	vpnDNSServers []net.IP
}

type Cookies map[string][]string

func (r *Config) UnmarshalYAML(unmarshal func(interface{}) error) error {
	type tmp Config
	var s struct {
		tmp
		PPPD       *bool    `yaml:"pppd"`
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

	if s.PPPD == nil {
		// PPPD is disable by default
		r.PPPD = false
	} else {
		r.PPPD = *s.PPPD
	}

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
		"passive",
		"ipcp-accept-local",
		"ipcp-accept-remote",
		"nodefaultroute",
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

	err := d.DecodeElement(&s, &start)
	if err != nil {
		return err
	}
	*o = Object(s.tmp)

	if v, err := url.QueryUnescape(s.TrafficControl); err != nil {
		return fmt.Errorf("failed to unescape %q: %s", s.TrafficControl, err)
	} else {
		if v := strings.TrimSpace(v); v != "" {
			if err = xml.Unmarshal([]byte(v), &o.TrafficControl); err != nil {
				return err
			}
		}
	}

	o.DNS = processIPs(s.DNS)
	o.DNS6 = processIPs(s.DNS6)
	o.ExcludeSubnets = processCIDRs(s.ExcludeSubnets)
	o.ExcludeSubnets6 = processCIDRs(s.ExcludeSubnets6)

	o.HDLCFraming, err = strToBool(s.HDLCFraming)
	if err != nil {
		return err
	}

	return nil
}

type agentInfo struct {
	XMLName              xml.Name `xml:"agent_info"`
	Type                 string   `xml:"type"`
	Version              string   `xml:"version"`
	Platform             string   `xml:"platform"`
	CPU                  string   `xml:"cpu"`
	JavaScript           Bool     `xml:"javascript"`
	ActiveX              Bool     `xml:"activex"`
	Plugin               Bool     `xml:"plugin"`
	LandingURI           string   `xml:"landinguri"`
	Model                string   `xml:"model,omitempty"`
	PlatformVersion      string   `xml:"platform_version,omitempty"`
	MACAddress           string   `xml:"mac_address,omitempty"`
	UniqueID             string   `xml:"unique_id,omitempty"`
	SerialNumber         string   `xml:"serial_number,omitempty"`
	AppID                string   `xml:"app_id,omitempty"`
	AppVersion           string   `xml:"app_version,omitempty"`
	JailBreak            *Bool    `xml:"jailbreak,omitempty"`
	VPNScope             string   `xml:"vpn_scope,omitempty"`
	VPNStartType         string   `xml:"vpn_start_type,omitempty"`
	LockedMode           Bool     `xml:"lockedmode"`
	VPNTunnelType        string   `xml:"vpn_tunnel_type,omitempty"`
	Hostname             Hostname `xml:"hostname"`
	BiometricFingerprint *Bool    `xml:"biometric_fingerprint,omitempty"`
	DevicePasscodeSet    *Bool    `xml:"device_passcode_set,omitempty"`
}

type clientData struct {
	XMLName       xml.Name `xml:"data"`
	Token         string   `xml:"token"`
	Version       string   `xml:"version"`
	RedirectURL   string   `xml:"redirect_url"`
	MaxClientData int      `xml:"max_client_data"`
}

type preConfigProfile struct {
	XMLName   xml.Name         `xml:"PROFILE"`
	Version   string           `xml:"VERSION,attr"`
	Servers   []Server         `xml:"SERVERS>SITEM"`
	Session   preConfigSession `xml:"SESSION"`
	DNSSuffix []string         `xml:"LOCATIONS>CORPORATE>DNSSUFFIX"`
}

type Server struct {
	Address string `xml:"ADDRESS"`
	Alias   string `xml:"ALIAS"`
}

type preConfigSession struct {
	Limited              Bool           `xml:"-"`
	SaveOnExit           Bool           `xml:"-"`
	SavePasswords        Bool           `xml:"-"`
	ReuseWinlogonCreds   Bool           `xml:"-"`
	ReuseWinlogonSession Bool           `xml:"-"`
	PasswordPolicy       PasswordPolicy `xml:"PASSWORD_POLICY"`
	Update               Update         `xml:"UPDATE"`
}

func (o *preConfigSession) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type tmp preConfigSession
	var s struct {
		tmp
		Limited              string `xml:"LIMITED,attr"`
		SaveOnExit           string `xml:"SAVEONEXIT"`
		SavePasswords        string `xml:"SAVEPASSWORDS"`
		ReuseWinlogonCreds   string `xml:"REUSEWINLOGONCREDS"`
		ReuseWinlogonSession string `xml:"REUSEWINLOGONSESSION"`
	}

	err := d.DecodeElement(&s, &start)
	if err != nil {
		return err
	}
	*o = preConfigSession(s.tmp)

	o.Limited, err = strToBool(s.Limited)
	if err != nil {
		return err
	}

	o.SaveOnExit, err = strToBool(s.SaveOnExit)
	if err != nil {
		return err
	}

	o.SavePasswords, err = strToBool(s.SavePasswords)
	if err != nil {
		return err
	}

	o.ReuseWinlogonCreds, err = strToBool(s.ReuseWinlogonCreds)
	if err != nil {
		return err
	}

	o.ReuseWinlogonSession, err = strToBool(s.ReuseWinlogonSession)
	if err != nil {
		return err
	}

	return nil
}

type PasswordPolicy struct {
	Mode    string `xml:"MODE"`
	Timeout int    `xml:"TIMEOUT"`
}

type Update struct {
	Mode Bool `xml:"-"`
}

func (o *Update) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type tmp Update
	var s struct {
		tmp
		Mode string `xml:"MODE"`
	}

	err := d.DecodeElement(&s, &start)
	if err != nil {
		return err
	}
	*o = Update(s.tmp)

	o.Mode, err = strToBool(s.Mode)
	if err != nil {
		return err
	}

	return nil
}
