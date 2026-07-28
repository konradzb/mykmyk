// Package target holds the small address helpers that make the rest of the code family-agnostic.
//
// The engine treats a target as an opaque string, which is why IPv6 support is mostly a matter of
// formatting it correctly at the two places family actually matters: attaching a link-local zone id
// before a tool dials, and bracketing an address before it is joined to a port. Everything stored -
// directory names, status rows, the Hosts and Ports tables - stays the bare canonical address, so a
// device found over v4 and over v6 lines up by MAC regardless of how any one tool spelled it.
package target

import (
	"net"
	"strings"
)

// IsIPv6 reports whether addr is an IPv6 address. A zone suffix (fe80::1%eth0) is tolerated so this
// works on the zoned form as well as the bare one.
func IsIPv6(addr string) bool {
	ip := net.ParseIP(bare(addr))
	return ip != nil && ip.To4() == nil
}

// IsLinkLocal reports whether addr is an IPv6 link-local unicast address (fe80::/10), the only kind
// that needs a zone id and an egress interface to be reachable.
func IsLinkLocal(addr string) bool {
	ip := net.ParseIP(bare(addr))
	return ip != nil && ip.To4() == nil && ip.IsLinkLocalUnicast()
}

// IsLinkLocalCIDR reports whether spec is a link-local CIDR such as fe80::/10. That is how the
// hosts file asks for link-local discovery, and how the nmap executor tells a multicast sweep apart
// from an ordinary ranged one.
func IsLinkLocalCIDR(spec string) bool {
	ip, _, err := net.ParseCIDR(spec)
	if err != nil {
		return false
	}
	return ip.To4() == nil && ip.IsLinkLocalUnicast()
}

// ScopeKey identifies one hosts-file entry, which for a link-local range has to include the
// interface: fe80::/10 on eth0.100 and fe80::/10 on eth0.200 are two different links that happen to
// share a CIDR, and scope.Load admits both for exactly that reason.
//
// Results are filed under this key - the output directory, the cache path, and the parent a
// discovered host is recorded against. Without the interface in it the two links overwrite each
// other's output, their hosts pile up under one parent so status attributes them to the wrong VLAN,
// and a re-run over a warm cache serves one link's host list to both - scanning every address out
// of an interface it was never seen on.
//
// Every other kind of entry is returned unchanged, so no IPv4 path moves.
func ScopeKey(spec, iface string) string {
	if iface == "" || !IsLinkLocalCIDR(spec) {
		return spec
	}
	return spec + "%" + iface
}

// Zoned attaches the egress interface to a link-local address as its zone id (fe80::1 -> fe80::1%eth0),
// which is what nmap's -e and Go's net dialer both need to reach it. A global v6 or v4 address needs
// no zone and is returned unchanged, as is an address that already carries one, so this is a no-op
// for every pre-IPv6 target.
func Zoned(addr, iface string) string {
	if iface == "" || strings.Contains(addr, "%") {
		return addr
	}
	if IsLinkLocal(addr) {
		return addr + "%" + iface
	}
	return addr
}

// DialAddr builds the host:port a native Go dialer (nc, smb, rdp) should connect to: the address
// with its zone attached when link-local, then bracketed if it is IPv6. For a v4 host it is exactly
// net.JoinHostPort's old behaviour, so nothing about an IPv4 scan changes.
func DialAddr(host, iface, port string) string {
	return net.JoinHostPort(Zoned(host, iface), port)
}

// bare strips a zone suffix so an address can be handed to net.ParseIP, which does not accept one.
func bare(addr string) string {
	if i := strings.Index(addr, "%"); i >= 0 {
		return addr[:i]
	}
	return addr
}
