package nmap

import "testing"

// The neighbour cache is one of the three discovery sources, and its lines vary: some carry a
// hardware address, some are still being resolved. Parsing has to pull the address and MAC out and
// flag the states that mean "probed but never answered", which are not live hosts.
func TestParseNeighbour(t *testing.T) {
	tests := []struct {
		name             string
		line             string
		addr, mac, state string
	}{
		{"reachable with mac", "fe80::1 dev eth0 lladdr 52:54:00:aa:bb:cc REACHABLE", "fe80::1", "52:54:00:aa:bb:cc", "REACHABLE"},
		{"stale with mac", "fe80::2 dev eth0 lladdr 52:54:00:11:22:33 STALE", "fe80::2", "52:54:00:11:22:33", "STALE"},
		{"failed has no mac", "fe80::9 dev eth0  FAILED", "fe80::9", "", "FAILED"},
		{"blank line", "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, mac, state := parseNeighbour(tt.line)
			if addr != tt.addr || mac != tt.mac || state != tt.state {
				t.Errorf("parseNeighbour(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tt.line, addr, mac, state, tt.addr, tt.mac, tt.state)
			}
		})
	}
}
