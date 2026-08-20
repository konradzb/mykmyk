package nmap

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	nmapWrapper "github.com/Ullaakut/nmap/v3"
	"github.com/kosmosec/mykmyk/internal/binary"
)

// The four IPv6 multicast discovery scripts, mirroring nmap_pipeline_ll.py. Each probes a different
// multicast group (plain echo, invalid-destination, SLAAC, MLD), so between them they catch hosts
// that stay silent to a bare ff02::1 echo. `newtargets` feeds whatever they find back in as scan
// targets, which is what makes them show up as "up" hosts in the result nmap writes.
const multicastScripts = "targets-ipv6-multicast-echo,targets-ipv6-multicast-invalid-dst," +
	"targets-ipv6-multicast-slaac,targets-ipv6-multicast-mld"

// discoverLinkLocal finds the IPv6 hosts on one link, reproducing the three-source union of
// nmap_pipeline_ll.py: an ICMPv6 echo to the all-nodes group to prime the neighbour cache, nmap's
// multicast discovery scripts (the structured backbone), and the kernel neighbour cache to catch
// anything the scripts missed. It returns a *Run so the result flows through the same
// discoveredEntries / RecordHosts machinery an IPv4 sweep uses - nothing downstream knows or cares
// that discovery went over IPv6.
//
// label is where the result is filed, and it carries the interface, because two hosts-file lines
// can name the same fe80::/10 on two different VLANs - see linkLabel.
//
// A link where nothing answered comes back as an empty *Run, not an error. An empty segment is a
// finding, not a failure, and reporting it as one would put a "not scanned reliably" block in the
// report for a link that was scanned perfectly well. The caller classifies it exactly as it already
// classifies an ARP sweep that swept a segment with nothing on it.
func discoverLinkLocal(iface string, label string, name string) (*nmapWrapper.Run, error) {
	if iface == "" {
		// Link-local is meaningless without an interface: the same fe80:: address can exist on
		// every VLAN, and only the egress interface says which link to probe.
		return nil, fmt.Errorf("link-local discovery needs an interface - add one to the hosts-file line, e.g. \"fe80::/10 eth0.100\"")
	}
	if _, err := os.Stat(label); os.IsNotExist(err) {
		os.Mkdir(label, 0775)
	}

	primeNeighbourCache(iface)

	run, err := runMulticastDiscovery(iface, label, name)
	if err != nil {
		// Non-fatal, exactly as nmap_pipeline_ll.py phase 0 treats it ("relying on the other
		// sources"). The multicast scripts are one of three discovery sources; the ICMPv6 echo
		// above has already primed the neighbour cache that mergeNeighbours reads next. Aborting the
		// whole segment because this single source errored - e.g. nmap failing to bind an IPv6
		// socket to the link-local source (mksock_bind_addr ... Invalid argument, seen on an
		// interface whose only IPv6 address is link-local) - is what turned a link full of hosts
		// into a FAILED segment. An empty run here lets mergeNeighbours recover them from the cache.
		log.Printf("nmap: link-local multicast discovery on %s exited abnormally, relying on ping + neighbour cache: %s", iface, err)
		run = &nmapWrapper.Run{}
	}
	mergeNeighbours(run, iface)
	return run, nil
}

// primeNeighbourCache sends a few ICMPv6 echoes to ff02::1 (all-nodes). Every IPv6 host on the link
// must answer (RFC 4443), which both discovers them directly and populates the kernel neighbour
// cache mergeNeighbours reads afterwards. Best effort: a multicast ping often reports a non-zero
// exit even when replies came back, so its error is logged and ignored.
func primeNeighbourCache(iface string) {
	if _, _, err := binary.Run("ping", []string{"-6", "-c", "3", "-I", iface, "ff02::1"}, nil); err != nil {
		log.Printf("nmap: link-local echo on %s did not complete cleanly (continuing): %s", iface, err)
	}
}

func runMulticastDiscovery(iface string, label string, name string) (*nmapWrapper.Run, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	defer cancel()
	// No WithTargets: the multicast scripts are prerule scripts that run before any host scan and
	// generate the targets themselves via newtargets, exactly as the reference script invokes nmap.
	args := []string{
		"-6", "-sn", "-n", "-e", iface,
		"--script", multicastScripts,
		"--script-args", "newtargets,interface=" + iface,
		"-oA", fmt.Sprintf("%s/%s", label, name),
	}
	scanner, err := nmapWrapper.NewScanner(ctx, nmapWrapper.WithCustomArguments(args...))
	if err != nil {
		return nil, err
	}
	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, err
	}
	if warnings != nil && len(*warnings) > 0 {
		log.Printf("nmap: link-local discovery warnings on %s: %s", iface, *warnings)
	}
	result.ToFile(fmt.Sprintf("./%s/%s.xml", label, name))
	return result, nil
}

// mergeNeighbours folds the kernel's IPv6 neighbour cache into a discovery result. Two things it
// adds that the scripts can miss: an address that answered neighbour discovery but not multicast
// echo, and the hardware address for a host the scripts found but could not attach a MAC to - and
// the MAC is what ties this host to its IPv4 self in the report.
func mergeNeighbours(run *nmapWrapper.Run, iface string) {
	out, _, err := binary.Run("ip", []string{"-6", "neigh", "show", "dev", iface}, nil)
	if err != nil {
		log.Printf("nmap: reading the neighbour cache for %s failed (continuing): %s", iface, err)
		return
	}

	index := make(map[string]int, len(run.Hosts))
	for i, h := range run.Hosts {
		for _, a := range h.Addresses {
			if a.AddrType == "ipv6" {
				index[a.Addr] = i
			}
		}
	}

	for _, line := range strings.Split(out.String(), "\n") {
		addr, mac, state := parseNeighbour(line)
		if addr == "" || state == "FAILED" || state == "INCOMPLETE" {
			// FAILED/INCOMPLETE are addresses we probed that never answered - not live hosts.
			continue
		}
		if i, ok := index[addr]; ok {
			if mac != "" && hostMac(run.Hosts[i]) == "" {
				run.Hosts[i].Addresses = append(run.Hosts[i].Addresses,
					nmapWrapper.Address{Addr: mac, AddrType: "mac"})
			}
			continue
		}
		host := nmapWrapper.Host{
			Status:    nmapWrapper.Status{State: "up", Reason: "nd-cache"},
			Addresses: []nmapWrapper.Address{{Addr: addr, AddrType: "ipv6"}},
		}
		if mac != "" {
			host.Addresses = append(host.Addresses, nmapWrapper.Address{Addr: mac, AddrType: "mac"})
		}
		run.Hosts = append(run.Hosts, host)
		index[addr] = len(run.Hosts) - 1
	}
}

// parseNeighbour pulls the address, hardware address and state out of one neighbour-cache row:
//
//	fe80::1 lladdr 52:54:00:aa:bb:cc router REACHABLE
//
// Fields rather than one pattern, because what sits between the lladdr and the state is open-ended
// - router, proxy, extern_learn, offload - and every flag a pattern fails to anticipate costs the
// MAC of that row. The MAC is the only thing tying this host to its IPv4 self, so losing one is
// losing the device from the comparison entirely.
func parseNeighbour(line string) (addr, mac, state string) {
	fields := strings.Fields(line)
	if len(fields) < 2 || net.ParseIP(fields[0]) == nil {
		return "", "", ""
	}
	for i, f := range fields {
		if f == "lladdr" && i+1 < len(fields) {
			mac = fields[i+1]
			break
		}
	}
	return fields[0], mac, fields[len(fields)-1]
}
