package sslscan

import "testing"

// sslTarget is the gate between an httpx URL and a target sslscan will accept. Two things it has to
// get right, both of which broke a real run: a cleartext http:// URL must be skipped (sslscan
// answers "Invalid target specified" for it, which used to abort the host's other URLs), and an
// https:// URL must be handed over as a bare host:port with the scheme stripped and a link-local
// zone preserved - url.Parse rejects the raw '%' zone httpx passes through, so this parses by hand.
func TestSslTarget(t *testing.T) {
	tests := []struct {
		name   string
		rawURL string
		iface  string
		want   string
		wantOk bool
	}{
		{"http is skipped", "http://192.168.1.5:80", "eth0", "", false},
		{"https ipv4 with port", "https://192.168.1.167:8443", "eth0", "192.168.1.167:8443", true},
		{"https ipv4 no port defaults 443", "https://192.168.1.5", "eth0", "192.168.1.5:443", true},
		{"https strips path", "https://192.168.1.1:8443/admin?q=1", "eth0", "192.168.1.1:8443", true},
		{"https link-local keeps raw zone", "https://[fe80::1%wlan0]:8443", "wlan0", "[fe80::1%wlan0]:8443", true},
		{"https link-local gets zone from iface", "https://[fe80::1]:8443", "wlan0", "[fe80::1%wlan0]:8443", true},
		{"https global ipv6 unchanged", "https://[2001:db8::1]:8443", "eth0", "[2001:db8::1]:8443", true},
		{"no scheme is skipped", "192.168.1.5:443", "eth0", "", false},
		{"non-tls scheme is skipped", "ftp://192.168.1.5:21", "eth0", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := sslTarget(tt.rawURL, tt.iface)
			if got != tt.want || ok != tt.wantOk {
				t.Errorf("sslTarget(%q, %q) = (%q, %t), want (%q, %t)",
					tt.rawURL, tt.iface, got, ok, tt.want, tt.wantOk)
			}
		})
	}
}
