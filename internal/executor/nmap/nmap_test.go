package nmap

import (
	"strings"
	"testing"

	nmapWrapper "github.com/Ullaakut/nmap/v3"
	"github.com/google/go-cmp/cmp"
	"github.com/kosmosec/mykmyk/internal/model"
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

func TestConvertToNmapMessage(t *testing.T) {
	tests := []struct {
		name    string
		hosts   []nmapWrapper.Host
		target  string
		iface   string
		want    []model.Message
		wantErr bool
	}{
		{
			name:   "single host port scan yields one message",
			hosts:  []nmapWrapper.Host{host("10.113.9.5", "up", "arp-response", 22, 80, 443)},
			target: "10.113.9.5",
			want: []model.Message{
				{Targets: []string{"10.113.9.5"}, Ports: []string{"22", "80", "443"}},
			},
		},
		{
			name: "discovery sweep fans out one message per live host",
			hosts: []nmapWrapper.Host{
				host("10.113.9.5", "up", "arp-response"),
				host("10.113.9.6", "up", "arp-response"),
				host("10.113.9.7", "up", "arp-response"),
			},
			target: "10.113.9.0/24",
			iface:  "eth0.100",
			want: []model.Message{
				{Targets: []string{"10.113.9.5"}, Ports: []string{}, Interface: "eth0.100"},
				{Targets: []string{"10.113.9.6"}, Ports: []string{}, Interface: "eth0.100"},
				{Targets: []string{"10.113.9.7"}, Ports: []string{}, Interface: "eth0.100"},
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
			want: []model.Message{
				{Targets: []string{"10.113.9.5"}, Ports: []string{}},
				{Targets: []string{"10.113.9.7"}, Ports: []string{}},
			},
		},
		{
			name: "our own address is dropped",
			hosts: []nmapWrapper.Host{
				host("10.113.9.1", "up", "localhost-response"),
				host("10.113.9.5", "up", "arp-response"),
			},
			target: "10.113.9.0/24",
			want: []model.Message{
				{Targets: []string{"10.113.9.5"}, Ports: []string{}},
			},
		},
		{
			name: "ports are per host, not pooled across hosts",
			hosts: []nmapWrapper.Host{
				host("10.113.9.5", "up", "arp-response", 22),
				host("10.113.9.6", "up", "arp-response", 3389),
			},
			target: "10.113.9.0/24",
			want: []model.Message{
				{Targets: []string{"10.113.9.5"}, Ports: []string{"22"}},
				{Targets: []string{"10.113.9.6"}, Ports: []string{"3389"}},
			},
		},
		{
			name:    "no hosts at all",
			hosts:   nil,
			target:  "10.113.9.0/24",
			wantErr: true,
		},
		{
			name:    "sweep where nothing answered",
			hosts:   []nmapWrapper.Host{host("10.113.9.6", "down", "no-response")},
			target:  "10.113.9.0/24",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := convertToNmapMessage(&nmapWrapper.Run{Hosts: tt.hosts}, tt.target, tt.iface)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("want an error, got messages: %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("convertToNmapMessage: %s", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("messages mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// A host with no address element must still be usable, otherwise a single-target scan could
// silently drop its own target.
func TestConvertToNmapMessageFallsBackToScannedTarget(t *testing.T) {
	h := nmapWrapper.Host{Status: nmapWrapper.Status{State: "up", Reason: "arp-response"}}
	got, err := convertToNmapMessage(&nmapWrapper.Run{Hosts: []nmapWrapper.Host{h}}, "10.113.9.5", "")
	if err != nil {
		t.Fatalf("convertToNmapMessage: %s", err)
	}
	want := []model.Message{{Targets: []string{"10.113.9.5"}, Ports: []string{}}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("messages mismatch (-want +got):\n%s", diff)
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
