package preflight

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/kosmosec/mykmyk/internal/api"
)

// summary is the part of a Finding the tests assert on: which task, of which type, at what severity.
// The exact Message/Fix wording is deliberately not compared so it can be reworded without breaking
// tests.
type summary struct {
	Task     string
	Type     api.TaskType
	Severity Severity
}

func summarize(fs []Finding) []summary {
	out := make([]summary, 0, len(fs))
	for _, f := range fs {
		out = append(out, summary{Task: f.Task, Type: f.Type, Severity: f.Severity})
	}
	return out
}

// fakeChecker reports the given binaries as installed and returns runOut from every probe.
func fakeChecker(installed []string, runOut string) Checker {
	set := make(map[string]bool, len(installed))
	for _, b := range installed {
		set[b] = true
	}
	return Checker{
		LookPath: func(bin string) (string, error) {
			if set[bin] {
				return "/usr/bin/" + bin, nil
			}
			return "", errors.New("not found")
		},
		Run: func(bin string, args ...string) (string, error) {
			return runOut, nil
		},
	}
}

func argTask(name string, typ api.TaskType, active bool, args ...string) api.Task {
	return api.Task{Name: name, Type: typ, Active: active, Run: map[string]interface{}{"args": args}}
}

func TestCheck(t *testing.T) {
	// A file that exists, for the absolute-path checks.
	existing := filepath.Join(t.TempDir(), "wordlist.txt")
	if err := os.WriteFile(existing, []byte("a\nb\n"), 0644); err != nil {
		t.Fatalf("write fixture: %s", err)
	}

	tests := []struct {
		name      string
		installed []string
		runOut    string
		tasks     []api.Task
		want      []summary
	}{
		{
			name:      "missing binary is an error",
			installed: nil,
			tasks:     []api.Task{argTask("ffuf-scan", api.FfufType, true, existing)},
			want:      []summary{{"ffuf-scan", api.FfufType, Error}},
		},
		{
			name:      "installed binary with existing paths is clean",
			installed: []string{"ffuf"},
			tasks:     []api.Task{argTask("ffuf-scan", api.FfufType, true, "-w", existing)},
			want:      nil,
		},
		{
			name:      "missing wordlist is an error even when the binary is present",
			installed: []string{"ffuf"},
			tasks:     []api.Task{argTask("ffuf-scan", api.FfufType, true, "-w", "/no/such/wordlist.txt")},
			want:      []summary{{"ffuf-scan", api.FfufType, Error}},
		},
		{
			name:      "httpx that does not identify as ProjectDiscovery is an error",
			installed: []string{"httpx"},
			runOut:    "usage: httpx [url]\n",
			tasks:     []api.Task{argTask("httpx-scan", api.HTTPXType, true, "-td")},
			want:      []summary{{"httpx-scan", api.HTTPXType, Error}},
		},
		{
			name:      "ProjectDiscovery httpx passes the identity probe",
			installed: []string{"httpx"},
			runOut:    "Current Version: v1.3.7\nprojectdiscovery.io\n",
			tasks:     []api.Task{argTask("httpx-scan", api.HTTPXType, true, "-td")},
			want:      nil,
		},
		{
			name:      "inactive tasks are skipped",
			installed: nil,
			tasks:     []api.Task{argTask("ffuf-scan", api.FfufType, false, "/no/such/wordlist.txt")},
			want:      nil,
		},
		{
			name:      "pure-Go task types need nothing",
			installed: nil,
			tasks: []api.Task{
				{Name: "nc-fingerprint", Type: api.Nc, Active: true},
				{Name: "smb-check", Type: api.Smb, Active: true},
				{Name: "rdp-check", Type: api.Rdp, Active: true},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := fakeChecker(tt.installed, tt.runOut)
			got := summarize(c.Check(api.Config{Workflow: api.Workflow{Tasks: tt.tasks}}).Findings)
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("findings mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNucleiTemplates covers the environment-dependent default-templates check, which reads $HOME and
// the actual templates directory nuclei will use - not merely whether its config JSON is present.
func TestNucleiTemplates(t *testing.T) {
	// writeConfig writes .templates-config.json pointing nuclei at dir (empty dir = no JSON at all).
	writeConfig := func(t *testing.T, home, dir string) {
		t.Helper()
		cfgDir := filepath.Join(home, ".config", "nuclei")
		if err := os.MkdirAll(cfgDir, 0755); err != nil {
			t.Fatalf("mkdir config: %s", err)
		}
		body := fmt.Sprintf(`{"nuclei-templates-directory":%q}`, dir)
		if err := os.WriteFile(filepath.Join(cfgDir, ".templates-config.json"), []byte(body), 0644); err != nil {
			t.Fatalf("write templates config: %s", err)
		}
	}
	// populate creates dir with one template file so it reads as a fetched template set.
	populate := func(t *testing.T, dir string) {
		t.Helper()
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatalf("mkdir templates: %s", err)
		}
		if err := os.WriteFile(filepath.Join(dir, "template.yaml"), []byte("id: x\n"), 0644); err != nil {
			t.Fatalf("write template: %s", err)
		}
	}

	run := func(t *testing.T, args ...string) []summary {
		t.Helper()
		c := fakeChecker([]string{"nuclei"}, "")
		return summarize(c.Check(api.Config{Workflow: api.Workflow{Tasks: []api.Task{
			argTask("nuclei-scan", api.NucleiType, true, args...),
		}}}).Findings)
	}
	nucleiErr := []summary{{"nuclei-scan", api.NucleiType, Error}}

	t.Run("never fetched (no config, no default dir) is an error", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir())
		if diff := cmp.Diff(nucleiErr, run(t, "-rl", "3"), cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})

	t.Run("config JSON present but its directory is gone is an error", func(t *testing.T) {
		// The testing2 shape: a leftover config points at a directory that does not exist (e.g. a
		// scan running as root with templates only ever fetched for another user).
		home := t.TempDir()
		t.Setenv("HOME", home)
		writeConfig(t, home, filepath.Join(home, "removed", "nuclei-templates"))
		if diff := cmp.Diff(nucleiErr, run(t, "-rl", "3"), cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})

	t.Run("config points at a populated directory is clean", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		dir := filepath.Join(home, ".local", "nuclei-templates")
		populate(t, dir)
		writeConfig(t, home, dir)
		if diff := cmp.Diff([]summary(nil), run(t, "-rl", "3"), cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})

	t.Run("default directory populated without config is clean", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv("HOME", home)
		populate(t, filepath.Join(home, ".local", "nuclei-templates"))
		if diff := cmp.Diff([]summary(nil), run(t, "-rl", "3"), cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})

	t.Run("explicit template path is checked by the path rule, not the default check", func(t *testing.T) {
		t.Setenv("HOME", t.TempDir()) // no templates, but config points elsewhere
		// One finding for the missing explicit path; the default-templates check stays quiet.
		if diff := cmp.Diff(nucleiErr, run(t, "-t", "/no/such/templates"), cmpopts.EquateEmpty()); diff != "" {
			t.Errorf("(-want +got):\n%s", diff)
		}
	})
}
