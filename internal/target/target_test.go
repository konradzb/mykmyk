package target

import "testing"

func TestIsIPv6(t *testing.T) {
	tests := map[string]bool{
		"10.113.9.5":     false,
		"192.168.1.0/24": false, // a CIDR is not an address
		"pentest.co.uk":  false,
		"2001:db8::1":    true,
		"fe80::1":        true,
		"fe80::1%eth0":   true, // zoned form still parses
		"::1":            true,
	}
	for in, want := range tests {
		if got := IsIPv6(in); got != want {
			t.Errorf("IsIPv6(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsLinkLocal(t *testing.T) {
	tests := map[string]bool{
		"fe80::1":      true,
		"fe80::1%eth0": true,
		"2001:db8::1":  false, // global
		"fc00::1":      false, // ULA
		"10.113.9.5":   false,
		"169.254.0.1":  false, // v4 link-local is not what we mean here
	}
	for in, want := range tests {
		if got := IsLinkLocal(in); got != want {
			t.Errorf("IsLinkLocal(%q) = %v, want %v", in, got, want)
		}
	}
}

func TestIsLinkLocalCIDR(t *testing.T) {
	tests := map[string]bool{
		"fe80::/10":      true,
		"fe80::/64":      true,
		"2001:db8::/32":  false,
		"10.113.9.0/24":  false,
		"192.168.1.0/24": false,
		"fe80::1":        false, // an address, not a CIDR
	}
	for in, want := range tests {
		if got := IsLinkLocalCIDR(in); got != want {
			t.Errorf("IsLinkLocalCIDR(%q) = %v, want %v", in, got, want)
		}
	}
}

// Two hosts-file lines can name the same fe80::/10 on different VLANs. If they key the same, one
// link's results overwrite the other's and a cached run scans every address out of both interfaces.
func TestScopeKey(t *testing.T) {
	tests := []struct {
		spec, iface, want string
	}{
		{"fe80::/10", "eth0.100", "fe80::/10%eth0.100"}, // the link, not just the range
		{"fe80::/10", "eth0.200", "fe80::/10%eth0.200"},
		{"fe80::/64", "eth0", "fe80::/64%eth0"},
		{"fe80::/10", "", "fe80::/10"},                 // no interface to key on
		{"10.113.9.0/24", "eth0.100", "10.113.9.0/24"}, // a routed range is unambiguous
		{"192.168.1.0/24", "", "192.168.1.0/24"},
		{"20.77.132.140", "eth0", "20.77.132.140"},
		{"pentest.co.uk", "", "pentest.co.uk"},
		{"2001:db8::/32", "eth0", "2001:db8::/32"}, // global v6 is reachable without a link
	}
	for _, tt := range tests {
		if got := ScopeKey(tt.spec, tt.iface); got != tt.want {
			t.Errorf("ScopeKey(%q, %q) = %q, want %q", tt.spec, tt.iface, got, tt.want)
		}
	}
}

func TestZoned(t *testing.T) {
	tests := []struct {
		addr, iface, want string
	}{
		{"fe80::1", "eth0.100", "fe80::1%eth0.100"}, // link-local gains the zone
		{"fe80::1", "", "fe80::1"},                  // no interface, nothing to attach
		{"fe80::1%eth0", "eth1", "fe80::1%eth0"},    // an existing zone is never rewritten
		{"2001:db8::1", "eth0", "2001:db8::1"},      // global v6 needs no zone
		{"10.113.9.5", "eth0.100", "10.113.9.5"},    // v4 is untouched
	}
	for _, tt := range tests {
		if got := Zoned(tt.addr, tt.iface); got != tt.want {
			t.Errorf("Zoned(%q, %q) = %q, want %q", tt.addr, tt.iface, got, tt.want)
		}
	}
}

func TestDialAddr(t *testing.T) {
	tests := []struct {
		host, iface, port, want string
	}{
		{"10.113.9.5", "", "445", "10.113.9.5:445"},            // v4 unchanged
		{"10.113.9.5", "eth0.100", "3389", "10.113.9.5:3389"},  // v4 ignores the interface
		{"2001:db8::1", "", "443", "[2001:db8::1]:443"},        // global v6 is bracketed
		{"fe80::1", "eth0.100", "80", "[fe80::1%eth0.100]:80"}, // link-local: zoned then bracketed
	}
	for _, tt := range tests {
		if got := DialAddr(tt.host, tt.iface, tt.port); got != tt.want {
			t.Errorf("DialAddr(%q, %q, %q) = %q, want %q", tt.host, tt.iface, tt.port, got, tt.want)
		}
	}
}
