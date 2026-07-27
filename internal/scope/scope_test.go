package scope

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func writeHostsFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "hosts")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write hosts file: %s", err)
	}
	return p
}

func TestLoad(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    []Entry
	}{
		{
			name:    "plain targets keep working",
			content: "pentest.co.uk\n20.77.132.140\ngoogle.com\n",
			want: []Entry{
				{Spec: "pentest.co.uk"},
				{Spec: "20.77.132.140"},
				{Spec: "google.com"},
			},
		},
		{
			name:    "interface column",
			content: "10.113.9.0/24    eth0.100\n10.113.10.0/24   eth0.200\n",
			want: []Entry{
				{Spec: "10.113.9.0/24", Interface: "eth0.100"},
				{Spec: "10.113.10.0/24", Interface: "eth0.200"},
			},
		},
		{
			name:    "mixed columns",
			content: "10.113.9.0/24 eth0.100\npentest.co.uk\n",
			want: []Entry{
				{Spec: "10.113.9.0/24", Interface: "eth0.100"},
				{Spec: "pentest.co.uk"},
			},
		},
		{
			name:    "comments and blank lines are skipped",
			content: "# a comment\n\n10.113.9.0/24 eth0.100  # trailing comment\n\n   \n20.77.132.140\n",
			want: []Entry{
				{Spec: "10.113.9.0/24", Interface: "eth0.100"},
				{Spec: "20.77.132.140"},
			},
		},
		{
			name:    "surrounding whitespace and tabs",
			content: "  10.113.9.0/24\t\teth0.100  \n\t20.77.132.140\t\n",
			want: []Entry{
				{Spec: "10.113.9.0/24", Interface: "eth0.100"},
				{Spec: "20.77.132.140"},
			},
		},
		{
			name:    "no trailing newline",
			content: "20.77.132.140",
			want:    []Entry{{Spec: "20.77.132.140"}},
		},
		{
			name:    "empty file",
			content: "",
			want:    []Entry{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Load(writeHostsFile(t, tt.content))
			if err != nil {
				t.Fatalf("Load: %s", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Load mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// Results are stored in a directory named after the target IP, so overlapping segments would
// write over each other. The run has to fail rather than silently merge them.
func TestLoadRejectsOverlappingSegments(t *testing.T) {
	tests := []struct {
		name    string
		content string
	}{
		{"identical cidrs on different interfaces", "192.168.1.0/24 eth0.100\n192.168.1.0/24 eth0.200\n"},
		{"one contains the other", "10.0.0.0/8 eth0.100\n10.113.9.0/24 eth0.200\n"},
		{"link-local twice on the same interface", "fe80::/10 eth0.100\nfe80::/10 eth0.100\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Load(writeHostsFile(t, tt.content))
			if err == nil {
				t.Fatal("expected an error for overlapping segments, got nil")
			}
			if !strings.Contains(err.Error(), "overlapping") {
				t.Errorf("error should explain the overlap, got: %s", err)
			}
		})
	}
}

func TestLoadAllowsDistinctSegments(t *testing.T) {
	content := "10.113.9.0/24 eth0.100\n10.113.10.0/24 eth0.200\n192.168.50.0/24 eth0.300\npentest.co.uk\n"
	got, err := Load(writeHostsFile(t, content))
	if err != nil {
		t.Fatalf("Load: %s", err)
	}
	if len(got) != 4 {
		t.Errorf("want 4 entries, got %d: %v", len(got), got)
	}
}

// Link-local space is scoped to an interface, so fe80::/10 on two different links is not an overlap;
// and a v4 range paired with the link-local range of the same link (the dual-stack layout) is the
// intended way to write the hosts file, not a collision.
func TestLoadAllowsLinkLocalAcrossInterfacesAndDualStack(t *testing.T) {
	content := "192.168.1.0/24 eth0.100\nfe80::/10 eth0.100\n10.113.10.0/24 eth0.200\nfe80::/10 eth0.200\n"
	got, err := Load(writeHostsFile(t, content))
	if err != nil {
		t.Fatalf("Load: %s", err)
	}
	if len(got) != 4 {
		t.Errorf("want 4 entries, got %d: %v", len(got), got)
	}
}
