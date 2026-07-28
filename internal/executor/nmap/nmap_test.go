package nmap

import (
	"database/sql"
	"os"
	"strings"
	"testing"

	nmapWrapper "github.com/Ullaakut/nmap/v3"
	"github.com/google/go-cmp/cmp"
	_ "github.com/mattn/go-sqlite3"

	"github.com/kosmosec/mykmyk/internal/model"
	"github.com/kosmosec/mykmyk/internal/sns"
	"github.com/kosmosec/mykmyk/internal/status"
)

func host(addr, state, reason string, ports ...uint16) nmapWrapper.Host {
	h := nmapWrapper.Host{
		Status:    nmapWrapper.Status{State: state, Reason: reason},
		Addresses: []nmapWrapper.Address{{Addr: addr, AddrType: "ipv4"}},
	}
	for _, p := range ports {
		h.Ports = append(h.Ports, nmapWrapper.Port{ID: p})
	}
	return h
}

// v6host builds a host answering on one or more IPv6 addresses, as link-local discovery finds it.
func v6host(mac string, addrs ...string) nmapWrapper.Host {
	h := nmapWrapper.Host{Status: nmapWrapper.Status{State: "up", Reason: "nd-cache"}}
	for _, a := range addrs {
		h.Addresses = append(h.Addresses, nmapWrapper.Address{Addr: a, AddrType: "ipv6"})
	}
	if mac != "" {
		h.Addresses = append(h.Addresses, nmapWrapper.Address{Addr: mac, AddrType: "mac"})
	}
	return h
}

func TestDiscoveredEntries(t *testing.T) {
	tests := []struct {
		name   string
		hosts  []nmapWrapper.Host
		target string
		want   []discoveredEntry
	}{
		{
			name:   "single host port scan yields one entry",
			hosts:  []nmapWrapper.Host{host("10.113.9.5", "up", "arp-response", 22, 80, 443)},
			target: "10.113.9.5",
			want: []discoveredEntry{
				{addr: "10.113.9.5", ports: []string{"22", "80", "443"}},
			},
		},
		{
			name: "discovery sweep fans out one entry per live host",
			hosts: []nmapWrapper.Host{
				host("10.113.9.5", "up", "arp-response"),
				host("10.113.9.6", "up", "arp-response"),
				host("10.113.9.7", "up", "arp-response"),
			},
			target: "10.113.9.0/24",
			want: []discoveredEntry{
				{addr: "10.113.9.5", ports: []string{}},
				{addr: "10.113.9.6", ports: []string{}},
				{addr: "10.113.9.7", ports: []string{}},
			},
		},
		{
			// Under -vvv nmap records hosts it found down too; forwarding those would put every
			// dead address in the range back into the port scan, defeating the whole gate.
			name: "down hosts are dropped",
			hosts: []nmapWrapper.Host{
				host("10.113.9.5", "up", "arp-response"),
				host("10.113.9.6", "down", "no-response"),
				host("10.113.9.7", "up", "arp-response"),
			},
			target: "10.113.9.0/24",
			want: []discoveredEntry{
				{addr: "10.113.9.5", ports: []string{}},
				{addr: "10.113.9.7", ports: []string{}},
			},
		},
		{
			name: "our own address is dropped",
			hosts: []nmapWrapper.Host{
				host("10.113.9.1", "up", "localhost-response"),
				host("10.113.9.5", "up", "arp-response"),
			},
			target: "10.113.9.0/24",
			want: []discoveredEntry{
				{addr: "10.113.9.5", ports: []string{}},
			},
		},
		{
			name: "ports are per host, not pooled across hosts",
			hosts: []nmapWrapper.Host{
				host("10.113.9.5", "up", "arp-response", 22),
				host("10.113.9.6", "up", "arp-response", 3389),
			},
			target: "10.113.9.0/24",
			want: []discoveredEntry{
				{addr: "10.113.9.5", ports: []string{"22"}},
				{addr: "10.113.9.6", ports: []string{"3389"}},
			},
		},
		{
			// The MAC is what ties this address to the same device's IPv4 side in the report.
			name:   "a host's every v6 address is scanned, all under one MAC",
			hosts:  []nmapWrapper.Host{v6host("52:54:00:aa:bb:cc", "fe80::5", "2001:db8::5")},
			target: "fe80::/10%eth0.100",
			want: []discoveredEntry{
				{addr: "fe80::5", mac: "52:54:00:aa:bb:cc", ports: []string{}},
				{addr: "2001:db8::5", mac: "52:54:00:aa:bb:cc", ports: []string{}},
			},
		},
		{
			// A host with no address element must still be usable, or a single-target scan could
			// silently drop its own target.
			name:   "a host with no address falls back to the scanned target",
			hosts:  []nmapWrapper.Host{{Status: nmapWrapper.Status{State: "up", Reason: "arp-response"}}},
			target: "10.113.9.5",
			want:   []discoveredEntry{{addr: "10.113.9.5", ports: []string{}}},
		},
		{
			name:   "no hosts at all",
			hosts:  nil,
			target: "10.113.9.0/24",
			want:   []discoveredEntry{},
		},
		{
			name:   "sweep where nothing answered",
			hosts:  []nmapWrapper.Host{host("10.113.9.6", "down", "no-response")},
			target: "10.113.9.0/24",
			want:   []discoveredEntry{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := discoveredEntries(&nmapWrapper.Run{Hosts: tt.hosts}, tt.target)
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(discoveredEntry{})); diff != "" {
				t.Errorf("entries mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// The live path: what discovery emits, and what it records for the report to correlate. The
// interface has to ride along on every message - a segment behind a trunk port is only reachable out
// of its own egress interface - and the addresses have to be filed under the scope key so two VLANs
// naming the same fe80::/10 stay apart.
func TestSendMessageToSNS(t *testing.T) {
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %s", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir: %s", err)
	}
	t.Cleanup(func() { os.Chdir(wd) })

	db, err := sql.Open("sqlite3", status.DSN)
	if err != nil {
		t.Fatalf("open db: %s", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(status.Schema); err != nil {
		t.Fatalf("create schema: %s", err)
	}

	bus := sns.New()
	bus.CreateTopic("ll-discovery")
	consumer := make(chan model.Message, 8)
	bus.AddConsumer("ll-discovery", "ST-scan", consumer)
	n := &Nmap{Name: "ll-discovery", sns: &bus}

	// One device, answering on its link-local and its global address, with 22 open. nmap reports
	// the MAC uppercase in its XML.
	h := v6host("52:54:00:AA:BB:CC", "fe80::5", "2001:db8::5")
	h.Ports = []nmapWrapper.Port{{ID: 22, Protocol: "tcp"}}
	run := &nmapWrapper.Run{Hosts: []nmapWrapper.Host{h}}

	if err := n.sendMessageToSNS(db, run, "fe80::/10%eth0.100", "eth0.100"); err != nil {
		t.Fatalf("sendMessageToSNS: %s", err)
	}
	close(consumer)

	got := make([]model.Message, 0)
	for m := range consumer {
		got = append(got, m)
	}
	want := []model.Message{
		{Targets: []string{"fe80::5"}, Ports: []string{"22"}, Interface: "eth0.100"},
		{Targets: []string{"2001:db8::5"}, Ports: []string{"22"}, Interface: "eth0.100"},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("messages mismatch (-want +got):\n%s", diff)
	}

	// Both addresses land on one device, under the MAC lower-cased so the neighbour cache's
	// spelling and nmap's agree.
	devices, err := status.Devices(db)
	if err != nil {
		t.Fatalf("Devices: %s", err)
	}
	if len(devices) != 1 {
		t.Fatalf("want one device, got %d: %+v", len(devices), devices)
	}
	if devices[0].Mac != "52:54:00:aa:bb:cc" {
		t.Errorf("MAC should be stored lower-cased, got %q", devices[0].Mac)
	}
	wantAddrs := []string{"2001:db8::5", "fe80::5"}
	if diff := cmp.Diff(wantAddrs, devices[0].V6Addrs); diff != "" {
		t.Errorf("device addresses mismatch (-want +got):\n%s", diff)
	}
	if diff := cmp.Diff([]string{"22/tcp"}, devices[0].PortsV6Only); diff != "" {
		t.Errorf("device ports mismatch (-want +got):\n%s", diff)
	}
}

// A CIDR target has to become a usable directory name, while everything already in use must map
// to itself so existing output paths and cache keys do not move.
func TestTargetLabel(t *testing.T) {
	tests := map[string]string{
		"10.113.9.5":    "10.113.9.5",
		"pentest.co.uk": "pentest.co.uk",
		"10.113.9.0/24": "10.113.9.0_24",
		"172.16.0.0/12": "172.16.0.0_12",
		"2001:db8::1":   "2001:db8::1",
		"10.0.0.0/8":    "10.0.0.0_8",
	}
	for in, want := range tests {
		if got := targetLabel(in); got != want {
			t.Errorf("targetLabel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestConvertNmapResultToStringReportsLivenessWhenNoPorts(t *testing.T) {
	// A -sn sweep finds hosts but no ports; the report should say what it found rather than
	// rendering an empty block.
	run := &nmapWrapper.Run{Hosts: []nmapWrapper.Host{
		host("10.113.9.5", "up", "arp-response"),
		host("10.113.9.6", "down", "no-response"),
	}}
	got := convertNmapResultToString(run, "10.113.9.0/24")
	if len(got) != 1 {
		t.Fatalf("want 1 line for the single live host, got %d: %v", len(got), got)
	}
	if want := "10.113.9.5"; !strings.Contains(got[0], want) {
		t.Errorf("line %q should name the live host %q", got[0], want)
	}
}
