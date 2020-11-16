package netaddr

import (
	"fmt"
	"net"
)

// IPRange range of ips not necessarily aligned to a power of 2
type IPRange struct {
	First, Last net.IP
}

func (r *IPRange) String() string {
	return fmt.Sprintf("[%s,%s]", r.First, r.Last)
}

// IPRangeFromIPNet get an IPRange from an *ip.Net
func IPRangeFromIPNet(cidr *net.IPNet) *IPRange {
	return &IPRange{
		First: NetworkAddr(cidr),
		Last:  BroadcastAddr(cidr),
	}
}

// Minus returns the ranges in r that are not in b
func (r *IPRange) Minus(b *IPRange) []*IPRange {
	diff := []*IPRange{}
	if IPLessThan(r.First, b.First) {
		diff = append(diff, &IPRange{First: r.First, Last: IPMin(r.Last, decrementIP(b.First))})
	}

	if IPLessThan(b.Last, r.Last) {
		diff = append(diff, &IPRange{First: IPMax(r.First, incrementIP(b.Last)), Last: r.Last})
	}
	return diff
}

// Contains returns true if b is contained in r
func (r *IPRange) Contains(b *IPRange) bool {
	if (IPLessThan(r.First, b.First) || r.First.Equal(b.First)) &&
		(IPLessThan(b.Last, r.Last) || r.Last.Equal(b.Last)) {
		return true
	}
	return false
}
