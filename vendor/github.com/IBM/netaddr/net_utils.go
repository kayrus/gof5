package netaddr

import (
	"bytes"
	"fmt"
	"math/big"
	"net"
	"strings"
)

// NetSize returns the size of the given IPNet in terms of the number of
// addresses. It always includes the network and broadcast addresses.
func NetSize(n *net.IPNet) *big.Int {
	ones, bits := n.Mask.Size()
	return big.NewInt(0).Lsh(big.NewInt(1), uint(bits-ones))
}

// ParseIP is like net.ParseIP except that it parses IPv4 addresses as 4 byte
// addresses instead of 16-byte mapped IPv6 addresses. This has been one of my
// biggest gripes against the net package.
func ParseIP(address string) net.IP {
	if strings.Contains(address, ":") {
		return net.ParseIP(address)
	}
	return net.ParseIP(address).To4()
}

// ParseCIDR is like net.ParseCIDR except that it parses IPv4 addresses as 4
// byte addresses instead of 16-byte mapped IPv6 addresses. Much like ParseIP.
func ParseCIDR(cidr string) (net.IP, *net.IPNet, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return net.IP{}, nil, err
	}

	if strings.Contains(cidr, ":") {
		return ip, ipNet, nil
	}
	return ip.To4(), ipNet, nil
}

// ParseCIDRToNet is like ParseCIDR except that it only returns one *net.IPNet
// that unifies the IP address and the mask. It leaves out the network address
// which ParseCIDR returns. This may be considered an abuse of the IPNet
// construct as it is documented that IP is supposed to be the "network
// number". However, the public IPNet interface does not dissallow it and this
// usage has been spotted in the wild.
func ParseCIDRToNet(cidr string) (*net.IPNet, error) {
	ip, ipNet, err := ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	return &net.IPNet{IP: ip, Mask: ipNet.Mask}, nil
}

// ParseNet parses an IP network from a CIDR. Unlike net.ParseCIDR, it does not
// allow a CIDR where the host part is non-zero. For example, the following
// CIDRs will result in an error: 203.0.113.1/24, 2001:db8::1/64, 10.0.20.0/20
func ParseNet(cidr string) (parsed *net.IPNet, err error) {
	ip, parsed, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if !ip.Equal(parsed.IP) {
		err = fmt.Errorf("Host part is not zero")
		return nil, err
	}
	return
}

// NewIP returns a new IP with the given size. The size must be 4 for IPv4 and
// 16 for IPv6.
func NewIP(size int) net.IP {
	if size == 4 {
		return net.ParseIP("0.0.0.0").To4()
	}
	if size == 16 {
		return net.ParseIP("::")
	}
	panic("Bad value for size")
}

// NetworkAddr returns the first address in the given network, or the network address.
func NetworkAddr(n *net.IPNet) net.IP {
	network := NewIP(len(n.IP))
	for i := 0; i < len(n.IP); i++ {
		network[i] = n.IP[i] & n.Mask[i]
	}
	return network
}

// BroadcastAddr returns the last address in the given network, or the broadcast address.
func BroadcastAddr(n *net.IPNet) net.IP {
	// The golang net package doesn't make it easy to calculate the broadcast address. :(
	broadcast := NewIP(len(n.IP))
	for i := 0; i < len(n.IP); i++ {
		broadcast[i] = n.IP[i] | ^n.Mask[i]
	}
	return broadcast
}

// ContainsNet returns true if net2 is a subset of net1. To be clear, it
// returns true if net1 == net2 also.
func ContainsNet(net1, net2 *net.IPNet) bool {
	// If the two networks are different IP versions, return false
	if len(net1.IP) != len(net2.IP) {
		return false
	}
	if !net1.Contains(net2.IP) {
		return false
	}
	if !net1.IP.Equal(net2.IP) {
		return true
	}
	return bytes.Compare(net1.Mask, net2.Mask) <= 0
}

// netDifference returns the set difference a - b. It returns the list of CIDRs
// in order from largest to smallest. They are *not* sorted by network IP.
func netDifference(a, b *net.IPNet) (result []*net.IPNet) {
	// If the two networks are different IP versions, return a
	if len(a.IP) != len(b.IP) {
		return []*net.IPNet{a}
	}

	// If b contains a then the difference is empty
	if ContainsNet(b, a) {
		return
	}
	// If a doesn't contain b then the difference is equal to a
	if !ContainsNet(a, b) {
		return []*net.IPNet{a}
	}

	// If two nets overlap then one must contain the other. At this point, we
	// know a contains b and b is smaller than a. Cut a in half and recurse on
	// the one that overlaps
	first, second := divideNetInHalf(a)
	if bytes.Compare(b.IP, second.IP) < 0 {
		return append([]*net.IPNet{second}, netDifference(first, b)...)
	}
	return append([]*net.IPNet{first}, netDifference(second, b)...)
}

// divideNetInHalf returns the given net as two equally sized halves
func divideNetInHalf(n *net.IPNet) (a, b *net.IPNet) {
	// Get the size of the original netmask
	ones, bits := n.Mask.Size()

	// Netmask has one more 1. Net is half the size of original.
	mask := net.CIDRMask(ones+1, bits)

	// Create a new IP to fill in for the second half
	ip := net.ParseIP("::")
	if bits == 32 {
		ip = net.ParseIP("0.0.0.0").To4()
	}
	// Fill in the new IP
	for i := 0; i < bits/8; i++ {
		// Puts a 1 in the new bit since this is the second half
		extraOne := mask[i] ^ n.Mask[i]
		// New IP is the same as old IP with the extra one at the end
		ip[i] = mask[i] & (n.IP[i] | extraOne)
	}

	a = &net.IPNet{IP: n.IP, Mask: mask}
	b = &net.IPNet{IP: ip, Mask: mask}
	return
}

// canCombineNets returns true if the two networks, a and b, can be combined
// into one larger cidr twice the size. If true, it returns the combined
// network.
func canCombineNets(a, b *net.IPNet) (ok bool, newNet *net.IPNet) {
	if a.IP.Equal(b.IP) {
		return
	}
	if bytes.Compare(a.Mask, b.Mask) != 0 {
		return
	}
	ones, bits := a.Mask.Size()
	newNet = &net.IPNet{IP: a.IP, Mask: net.CIDRMask(ones-1, bits)}
	if newNet.Contains(b.IP) {
		ok = true
		return
	}
	return
}

// ipToNet converts the given IP to a /32 or /128 network depending on the type
// of address.
func ipToNet(ip net.IP) *net.IPNet {
	size := 8 * len(ip)
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(size, size)}
}

// incrementIP returns the given IP + 1
func incrementIP(ip net.IP) (result net.IP) {
	result = make([]byte, len(ip)) // start off with a nice empty ip of proper length

	carry := true
	for i := len(ip) - 1; i >= 0; i-- {
		result[i] = ip[i]
		if carry {
			result[i]++
			if result[i] != 0 {
				carry = false
			}
		}
	}
	return
}

// decrementIP returns the given IP - 1
func decrementIP(ip net.IP) (result net.IP) {
	result = make([]byte, len(ip)) // start off with a nice empty ip of proper length

	borrow := true
	for i := len(ip) - 1; i >= 0; i-- {
		result[i] = ip[i]
		if borrow {
			result[i]--
			if result[i] != 255 { // if we overflowed, we'd end up here
				borrow = false
			}
		}
	}
	return
}

// expandNet returns a slice containing all of the IPs in the given net up to
// the given limit
func expandNet(n *net.IPNet, limit int) []net.IP {
	ones, bits := n.Mask.Size()

	size := limit
	max := 1 << 30
	if bits-ones < 30 {
		max = 1 << uint(bits-ones)
	}
	if max < size {
		size = max
	}
	result := make([]net.IP, size)
	next := n.IP
	for i := 0; i < size; i++ {
		result[i] = next[:]
		next = incrementIP(next)
	}
	return result
}

// IPLessThan compare two ip addresses true
// ordered by ipv4 first, then ipv6 later
// then by section left-most is most significant
// e.g.
// 10.0.0.0
// 10.0.0.1
// 192.169.0.1
// 2001:db8::
func IPLessThan(a, b net.IP) bool {
	if len(a) != len(b) { // ipv6 comes after ipv4
		return len(a) < len(b)
	}
	for i := range a { // go left to right and compare each one
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false // they are equal
}

// IPMin returns the minimum of a and b
func IPMin(a, b net.IP) net.IP {
	if IPLessThan(a, b) {
		return a
	}
	return b
}

// IPMax returns the maximum of a and b
func IPMax(a, b net.IP) net.IP {
	if IPLessThan(a, b) {
		return b
	}
	return a
}

// IPv4 returns the IP address (in 4-byte form) of the
// IPv4 address a.b.c.d.
func IPv4(a, b, c, d byte) net.IP {
	p := make(net.IP, net.IPv4len)
	p[0] = a
	p[1] = b
	p[2] = c
	p[3] = d
	return p
}

// IPv4Net returns the IPNet (in 4-byte form) of the
// IPv4 address a.b.c.d/p.
func IPv4Net(a, b, c, d byte, p int) net.IPNet {
	return net.IPNet{
		IP:   IPv4(a, b, c, d),
		Mask: net.CIDRMask(p, 8*net.IPv4len),
	}
}
