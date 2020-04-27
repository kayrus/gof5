package pkg

import (
	"encoding/xml"
	"net/url"
)

const (
	cookiesPath = "cookies"
	userAgent   = "Mozilla/5.0 (X11; U; Linux i686; en-US; rv:1.9.1a2pre) Gecko/2008073000 Shredder/3.0a2pre ThunderBrowse/3.2.1.8"
)

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
	// TODO: parse CIDR + netmasks
	ExcludeSubnets  string         `xml:"ExcludeSubnets0"`
	ExcludeSubnets6 string         `xml:"ExcludeSubnets6_0"`
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

func (o *Object) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	type tmp Object
	var s struct {
		tmp
		TrafficControl string `xml:"TrafficControl0"`
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

	return nil
}
