package nmap

import (
	"context"
	"fmt"
	"log"
	"os"
	"regexp"
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

// neighLine pulls the address and, when present, the hardware address out of one `ip -6 neigh`
// row: "fe80::1 dev eth0 lladdr 52:54:00:aa:bb:cc REACHABLE". The lladdr group is optional because
// an entry can be listed without one; those are only useful if the address is otherwise unknown.
var neighLine = regexp.MustCompile(`^([0-9a-fA-F:]+)\s+.*?(?:lladdr\s+([0-9a-fA-F:]+))?\s+(\w+)$`)

// discoverLinkLocal finds the IPv6 hosts on one link, reproducing the three-source union of
// nmap_pipeline_ll.py: an ICMPv6 echo to the all-nodes group to prime the neighbour cache, nmap's
// multicast discovery scripts (the structured backbone), and the kernel neighbour cache to catch
// anything the scripts missed. It returns a *Run so the result flows through the same
// convertToNmapMessage / RecordHosts machinery an IPv4 sweep uses - nothing downstream knows or
// cares that discovery went over IPv6.
func discoverLinkLocal(iface string, name string) (*nmapWrapper.Run, error) {
	if iface == "" {
		// Link-local is meaningless without an interface: the same fe80:: address can exist on
		// every VLAN, and only the egress interface says which link to probe.
		return nil, fmt.Errorf("link-local discovery needs an interface - add one to the hosts-file line, e.g. \"fe80::/10 eth0.100\"")
	}
	label := targetLabel("fe80::/10")
	if _, err := os.Stat(label); os.IsNotExist(err) {
		os.Mkdir(label, 0775)
	}

	primeNeighbourCache(iface)

	run, err := runMulticastDiscovery(iface, label, name)
	if err != nil {
		return nil, err
	}
	mergeNeighbours(run, iface)

	if len(usableHosts(run)) == 0 {
		return nil, ErrEmptyNmapScanResult
	}
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

func parseNeighbour(line string) (addr, mac, state string) {
	m := neighLine.FindStringSubmatch(strings.TrimSpace(line))
	if m == nil {
		return "", "", ""
	}
	return m[1], m[2], m[3]
}

func usableHosts(run *nmapWrapper.Run) []nmapWrapper.Host {
	hosts := make([]nmapWrapper.Host, 0, len(run.Hosts))
	for _, h := range run.Hosts {
		if isHostUsable(h) {
			hosts = append(hosts, h)
		}
	}
	return hosts
}
