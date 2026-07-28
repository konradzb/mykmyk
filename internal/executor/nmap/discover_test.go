package nmap

import "testing"

// The neighbour cache is one of the three discovery sources, and its lines vary: some carry a
// hardware address, some are still being resolved. Parsing has to pull the address and MAC out and
// flag the states that mean "probed but never answered", which are not live hosts.
//
// The rows below are the ones `ip -6 neigh show dev eth0` actually prints. Naming the device in the
// command drops the "dev eth0" column from every row, and any neighbour can carry a flag between
// its lladdr and its state - which is where an earlier pattern-based parser silently lost the MAC,
// and with it the device's link to its IPv4 self.
func TestParseNeighbour(t *testing.T) {
	tests := []struct {
		name             string
		line             string
		addr, mac, state string
	}{
		{"reachable with mac", "fe80::1 lladdr 52:54:00:aa:bb:cc REACHABLE", "fe80::1", "52:54:00:aa:bb:cc", "REACHABLE"},
		{"stale with mac", "fe80::2 lladdr 52:54:00:11:22:33 STALE", "fe80::2", "52:54:00:11:22:33", "STALE"},
		{"router flag keeps its mac", "fe80::1 lladdr 52:54:00:aa:bb:cc router REACHABLE", "fe80::1", "52:54:00:aa:bb:cc", "REACHABLE"},
		{"router flag when stale", "fe80::1 lladdr 52:54:00:aa:bb:cc router STALE", "fe80::1", "52:54:00:aa:bb:cc", "STALE"},
		{"extern_learn flag", "fe80::3 lladdr 52:54:00:44:55:66 extern_learn NOARP", "fe80::3", "52:54:00:44:55:66", "NOARP"},
		{"global address in the cache", "2001:db8::5 lladdr 52:54:00:77:88:99 STALE", "2001:db8::5", "52:54:00:77:88:99", "STALE"},
		{"dev column when not filtered", "fe80::4 dev eth0 lladdr 52:54:00:aa:bb:cc REACHABLE", "fe80::4", "52:54:00:aa:bb:cc", "REACHABLE"},
		{"failed has no mac", "fe80::9  FAILED", "fe80::9", "", "FAILED"},
		{"incomplete has no mac", "fe80::a INCOMPLETE", "fe80::a", "", "INCOMPLETE"},
		{"blank line", "", "", "", ""},
		{"not an address", "no such device", "", "", ""},
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
