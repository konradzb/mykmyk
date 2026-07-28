package httpx

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

// A link-local target reaches httpx as [fe80::1%eth0]:80, so the URL it hands back carries a raw
// zone - which is not a valid URI, because a zone has to be written %25. url.Parse returns nil for
// it, and the nil used to be dereferenced here: a panic in the httpx goroutine ends the whole run
// and loses every other task's results along with the report.
func TestResolvePortIfEmptyHandlesUnparseableURLs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want []string
	}{
		{
			name: "zoned link-local url survives unchanged",
			in:   []string{"http://[fe80::1%eth0]:80"},
			want: []string{"http://[fe80::1%eth0]:80"},
		},
		{
			// The zoned form is passed through, the rest of the batch still gets its port resolved.
			name: "one bad url does not lose the others",
			in:   []string{"http://[fe80::1%eth0.100]:8080", "https://10.113.9.5", "http://10.113.9.6"},
			want: []string{"http://[fe80::1%eth0.100]:8080", "https://10.113.9.5:443", "http://10.113.9.6:80"},
		},
		{
			name: "global v6 parses and keeps its port",
			in:   []string{"https://[2001:db8::1]:443"},
			want: []string{"https://[2001:db8::1]:443"},
		},
		{
			name: "ipv4 behaviour is unchanged",
			in:   []string{"http://10.113.9.5", "https://10.113.9.5:8443"},
			want: []string{"http://10.113.9.5:80", "https://10.113.9.5:8443"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolvePortIfEmpty(tt.in)
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("resolvePortIfEmpty mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
