// Package scope parses the hosts file. It lives outside the filesystem executor because the same
// file has to be read by commands that never run a scan - status has to know which networks were
// asked for so it can group the hosts found under them, and find has to walk the same targets.
package scope

import (
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/kosmosec/mykmyk/internal/target"
)

// Entry is one line of the hosts file: a target plus, optionally, the interface which reaches it.
// The interface column exists for trunk ports, where each VLAN sits behind its own sub-interface
// and ARP discovery has to leave through the right one.
type Entry struct {
	Spec      string
	Interface string
}

// Load reads the hosts file. Each non-empty line is "<target> [<interface>]", where target is an
// IP, CIDR or domain and the optional second column names the egress interface, e.g.
//
//	10.113.9.0/24    eth0.100
//	10.113.10.0/24   eth0.200
//	pentest.co.uk                # no interface -> kernel routing
//
// A bare one-column line keeps its original meaning, so existing hosts files are unaffected.
func Load(filePath string) ([]Entry, error) {
	rawScope, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read scope from file %v: %w", filePath, err)
	}
	entries := make([]Entry, 0)
	for _, line := range strings.Split(string(rawScope), "\n") {
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		entry := Entry{Spec: fields[0]}
		if len(fields) > 1 {
			entry.Interface = fields[1]
		}
		entries = append(entries, entry)
	}
	if err := checkOverlap(entries); err != nil {
		return nil, err
	}
	return entries, nil
}

// checkOverlap rejects a scope whose segments cover the same addresses. Scan results are stored
// in a directory named after the target IP, so two VLANs both carrying, say, 192.168.1.0/24 would
// silently write into each other's output. Failing up front beats corrupting the report.
//
// It is also what lets status attribute a discovered host to exactly one network: with overlapping
// segments ruled out, an address can belong to at most one entry in the file.
func checkOverlap(entries []Entry) error {
	type segment struct {
		entry Entry
		ipNet *net.IPNet
	}
	seen := make([]segment, 0, len(entries))
	for _, e := range entries {
		_, ipNet, err := net.ParseCIDR(e.Spec)
		if err != nil {
			continue // single IP, hostname or domain: nothing to compare
		}
		for _, other := range seen {
			if other.ipNet.Contains(ipNet.IP) || ipNet.Contains(other.ipNet.IP) {
				// Link-local address space is scoped to an interface: fe80::/10 on eth0.100 and
				// fe80::/10 on eth0.200 are two different links that happen to share a CIDR, not a
				// collision. Only a shared interface makes two link-local entries overlap. (A v4
				// entry and a v6 one never reach here - Contains is false across families.)
				if target.IsLinkLocalCIDR(e.Spec) && target.IsLinkLocalCIDR(other.entry.Spec) &&
					e.Interface != other.entry.Interface {
					continue
				}
				return fmt.Errorf(
					"scope entries %q (%s) and %q (%s) cover overlapping address space; "+
						"results are stored per IP address and would collide - "+
						"scan these segments in separate runs, in separate folders",
					other.entry.Spec, describeInterface(other.entry.Interface),
					e.Spec, describeInterface(e.Interface))
			}
		}
		seen = append(seen, segment{entry: e, ipNet: ipNet})
	}
	return nil
}

func describeInterface(iface string) string {
	if iface == "" {
		return "no interface"
	}
	return iface
}
