package cmd

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/kosmosec/mykmyk/internal/api"
	"gopkg.in/yaml.v2"
)

func TestProfileName(t *testing.T) {
	tests := map[string]string{
		"config.yml":       defaultProfile,
		"config.yaml":      defaultProfile,
		"config-ARP.yaml":  "ARP",
		"config-ping.yaml": "ping",
		"config-ARP.yml":   "ARP",
	}
	for in, want := range tests {
		if got := profileName(in); got != want {
			t.Errorf("profileName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseDescription(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "leading description",
			raw:  "# description: External scan.\noutputFile: ./out.html\n",
			want: "External scan.",
		},
		{
			name: "description after other comments",
			raw:  "# Some heading\n#\n# description: Internal L2.\n#\noutputFile: ./out.html\n",
			want: "Internal L2.",
		},
		{
			name: "no space after hash",
			raw:  "#description: Terse.\noutputFile: ./out.html\n",
			want: "Terse.",
		},
		{
			name: "indented comment",
			raw:  "   #   description:   Padded.  \noutputFile: ./out.html\n",
			want: "Padded.",
		},
		{
			name: "blank lines before the comment block",
			raw:  "\n\n# description: After blanks.\noutputFile: ./out.html\n",
			want: "After blanks.",
		},
		{
			name: "no description at all",
			raw:  "# just a heading\noutputFile: ./out.html\n",
			want: "",
		},
		{
			// A mention below the YAML body is not the file's summary and must not be picked up.
			name: "description below the body is ignored",
			raw:  "outputFile: ./out.html\nworkflow:\n  # description: not the summary\n  tasks: []\n",
			want: "",
		},
		{
			name: "empty file",
			raw:  "",
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseDescription([]byte(tt.raw)); got != tt.want {
				t.Errorf("parseDescription() = %q, want %q", got, tt.want)
			}
		})
	}
}

// Option 1 must always be the conservative choice, whatever the filenames sort to.
func TestLoadProfilesPutsDefaultFirst(t *testing.T) {
	profiles, err := loadProfiles()
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) < 2 {
		t.Fatalf("want at least 2 bundled templates, got %d", len(profiles))
	}
	if profiles[0].name != defaultProfile {
		t.Errorf("first template is %q, want %q", profiles[0].name, defaultProfile)
	}
	for _, p := range profiles {
		if p.description == "" {
			t.Errorf("template %q has no description; add a '# description:' line to %s", p.name, p.fileName)
		}
	}
}

func testProfiles() []profile {
	return []profile{
		{name: "default", description: "External scan.", fileName: "config.yml"},
		{name: "ARP", description: "Internal L2.", fileName: "config-ARP.yaml"},
	}
}

func TestPromptForProfile(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"by number", "2\n", "ARP"},
		{"first by number", "1\n", "default"},
		{"empty accepts the default", "\n", "default"},
		{"by name", "ARP\n", "ARP"},
		{"by lowercase name", "arp\n", "ARP"},
		{"by name with whitespace", "  ARP  \n", "ARP"},
		{"retries after an out-of-range number", "9\n2\n", "ARP"},
		{"retries after an unknown name", "nope\nARP\n", "ARP"},
		{"eof with no input accepts the default", "", "default"},
		{"input without trailing newline", "ARP", "ARP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out bytes.Buffer
			got, err := promptForProfile(testProfiles(), bufio.NewReader(strings.NewReader(tt.input)), &out)
			if err != nil {
				t.Fatalf("promptForProfile: %s", err)
			}
			if got.name != tt.want {
				t.Errorf("chose %q, want %q", got.name, tt.want)
			}
			if !strings.Contains(out.String(), "Available config templates") {
				t.Error("picker should list the templates")
			}
		})
	}
}

func TestPromptForProfileGivesUpAfterRepeatedBadInput(t *testing.T) {
	var out bytes.Buffer
	_, err := promptForProfile(testProfiles(), bufio.NewReader(strings.NewReader("nope\nnope\nnope\nnope\n")), &out)
	if err == nil {
		t.Fatal("want an error after repeated invalid input, got nil")
	}
}

// The picker and the overwrite prompt read from the same stdin one after the other. bufio reads
// ahead, so giving each its own reader would let the first swallow the second's answer - the
// overwrite question would then see EOF and silently decline. Both must share one reader.
func TestPromptsShareOneReaderWithoutSwallowingInput(t *testing.T) {
	shared := bufio.NewReader(strings.NewReader("2\ny\n"))
	var out bytes.Buffer

	chosen, err := promptForProfile(testProfiles(), shared, &out)
	if err != nil {
		t.Fatalf("promptForProfile: %s", err)
	}
	if chosen.name != "ARP" {
		t.Fatalf("picker chose %q, want ARP", chosen.name)
	}

	// The "y" must still be readable by the next prompt.
	line, err := shared.ReadString('\n')
	if err != nil && line == "" {
		t.Fatal("second prompt found no input; the picker swallowed it")
	}
	if got := strings.TrimSpace(line); got != "y" {
		t.Errorf("second prompt read %q, want \"y\"", got)
	}
}

func TestFindProfileUnknownNameListsAvailable(t *testing.T) {
	_, err := findProfile(testProfiles(), "nope")
	if err == nil {
		t.Fatal("want an error for an unknown template")
	}
	for _, want := range []string{"default", "ARP"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should list template %q, got: %s", want, err)
		}
	}
}

func TestConfirmOverwrite(t *testing.T) {
	// A file that does not exist needs no confirmation.
	missing := filepath.Join(t.TempDir(), "config.yml")
	if !confirmOverwrite(missing, bufio.NewReader(strings.NewReader("")), &bytes.Buffer{}) {
		t.Error("a missing config should be written without asking")
	}

	// An existing one does. Not a terminal under `go test`, so this exercises the
	// non-interactive path: overwrite silently, exactly as init behaved before.
	existing := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(existing, []byte("outputFile: ./x.html\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if !confirmOverwrite(existing, bufio.NewReader(strings.NewReader("n\n")), &bytes.Buffer{}) {
		t.Error("without a terminal, an existing config should be overwritten as before")
	}
}

// chooseProfile must never block a script: with no terminal it resolves to the default template
// instead of waiting on a prompt.
func TestChooseProfile(t *testing.T) {
	profiles := testProfiles()

	got, err := chooseProfile(profiles, "ARP", bufio.NewReader(strings.NewReader("")), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got.name != "ARP" {
		t.Errorf("--profile ARP chose %q", got.name)
	}

	got, err = chooseProfile(profiles, "", bufio.NewReader(strings.NewReader("")), &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	if got.name != defaultProfile {
		t.Errorf("non-interactive init chose %q, want %q", got.name, defaultProfile)
	}

	if _, err := chooseProfile(profiles, "nope", bufio.NewReader(strings.NewReader("")), &bytes.Buffer{}); err == nil {
		t.Error("an unknown --profile should error")
	}
}

// Every bundled template must be a usable workflow, not just valid YAML.
func TestBundledProfilesAreValidWorkflows(t *testing.T) {
	profiles, err := loadProfiles()
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range profiles {
		t.Run(p.name, func(t *testing.T) {
			raw, err := configProfiles.ReadFile("configs/" + p.fileName)
			if err != nil {
				t.Fatal(err)
			}
			var cfg api.Config
			if err := yaml.Unmarshal(raw, &cfg); err != nil {
				t.Fatalf("unmarshal: %s", err)
			}
			if len(cfg.Workflow.Tasks) == 0 {
				t.Fatal("template defines no tasks")
			}
			defined := map[string]bool{}
			for _, task := range cfg.Workflow.Tasks {
				defined[task.Name] = true
			}
			for _, task := range cfg.Workflow.Tasks {
				if task.Source != "" && !defined[task.Source] {
					t.Errorf("task %q sources %q, which is not defined", task.Name, task.Source)
				}
				// A worker-pool task with no concurrency makes an unbuffered limiter and hangs.
				if task.Type != api.FilesystemType && task.Concurrency < 1 {
					t.Errorf("task %q has concurrency %d; it must be >= 1", task.Name, task.Concurrency)
				}
			}
		})
	}
}

// The description comment must not change how the default template is interpreted.
func TestDefaultProfileSemanticsUnchangedByDescriptionComment(t *testing.T) {
	raw, err := configProfiles.ReadFile("configs/config.yml")
	if err != nil {
		t.Fatal(err)
	}
	var withComment api.Config
	if err := yaml.Unmarshal(raw, &withComment); err != nil {
		t.Fatal(err)
	}

	stripped := []string{}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "# "+descriptionMarker) {
			continue
		}
		stripped = append(stripped, line)
	}
	var withoutComment api.Config
	if err := yaml.Unmarshal([]byte(strings.Join(stripped, "\n")), &withoutComment); err != nil {
		t.Fatal(err)
	}

	if diff := cmp.Diff(withoutComment, withComment); diff != "" {
		t.Errorf("description comment changed the parsed config (-without +with):\n%s", diff)
	}
}
