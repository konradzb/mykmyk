package cmd

import (
	"bufio"
	"embed"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/kosmosec/mykmyk/internal/api"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

// Every config in configs/ is a template for a different kind of engagement. Adding one is just
// dropping a file in the folder: config-<name>.yaml becomes profile <name>, plain config.yml is
// the default, and the "# description:" line in the file is what the picker shows.
//
//go:embed configs
var configProfiles embed.FS

const (
	configProfileDir = "configs"
	defaultProfile   = "default"
	// profileNamePrefix marks a non-default template: config-ARP.yaml -> profile "ARP".
	profileNamePrefix = "config-"
	// descriptionMarker introduces the one-line summary shown by the picker and --list.
	descriptionMarker = "description:"
	// maxPromptAttempts stops a misbehaving or looping input source from spinning forever.
	maxPromptAttempts = 3
)

type profile struct {
	name        string // the --profile value: "default", "ARP"
	description string // one-line summary for the picker; may be empty
	fileName    string // name within configs/
}

func NewConfig() *cobra.Command {
	var profileName string
	var list bool
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create config from a template",
		Long: "Create config.yml for mykmyk from one of the bundled templates.\n\n" +
			"Run without flags to pick a template interactively. Use --profile <name> to choose one\n" +
			"non-interactively (for scripts), or --list to see what is available.",
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := loadProfiles()
			if err != nil {
				return err
			}

			if list {
				printProfiles(profiles, os.Stdout)
				return nil
			}

			// One reader for every prompt in this command. bufio reads ahead, so a second
			// reader built over the same stdin would find the first one had already swallowed
			// the answer to the next question.
			stdin := bufio.NewReader(os.Stdin)

			chosen, err := chooseProfile(profiles, profileName, stdin, os.Stdout)
			if err != nil {
				return err
			}

			if !force && !confirmOverwrite(api.DefaultConfigName, stdin, os.Stdout) {
				fmt.Printf("Keeping the existing %s untouched.\n", api.DefaultConfigName)
				return nil
			}

			cfg, err := configProfiles.ReadFile(path.Join(configProfileDir, chosen.fileName))
			if err != nil {
				return err
			}
			if err := creatLocalConfig(cfg); err != nil {
				return err
			}
			if err := createGlobalConfig(cfg); err != nil {
				return err
			}
			fmt.Printf("Wrote the %q template to ./%s\n", chosen.name, api.DefaultConfigName)
			return nil
		},
	}
	// Default is empty rather than "default" so that "not passed" is distinguishable from
	// "passed as default" - only the former should open the picker.
	cmd.Flags().StringVar(&profileName, "profile", "", "Config template to write; skips the interactive picker (see --list)")
	cmd.Flags().BoolVar(&list, "list", false, "List available config templates")
	cmd.Flags().BoolVar(&force, "force", false, "Overwrite an existing config.yml without asking")

	return cmd
}

// chooseProfile resolves which template to write. An explicit --profile always wins. Otherwise we
// ask, but only when there is a human to answer: prompting a script or a CI job would hang it, so
// a non-terminal stdin silently falls back to the default template, which is how init behaved
// before the picker existed.
func chooseProfile(profiles []profile, requested string, in *bufio.Reader, out io.Writer) (profile, error) {
	if requested != "" {
		return findProfile(profiles, requested)
	}
	if !isInteractive() {
		return findProfile(profiles, defaultProfile)
	}
	return promptForProfile(profiles, in, out)
}

func isInteractive() bool {
	return term.IsTerminal(int(os.Stdin.Fd()))
}

// promptForProfile shows the templates and reads a choice: a list number, a template name
// (case-insensitively), or empty to accept the default. Reader and writer are parameters rather
// than os.Stdin/os.Stdout so the picker can be tested without a terminal.
func promptForProfile(profiles []profile, in *bufio.Reader, out io.Writer) (profile, error) {
	if len(profiles) == 0 {
		return profile{}, errors.New("no config templates are bundled with this binary")
	}
	printProfiles(profiles, out)

	for attempt := 0; attempt < maxPromptAttempts; attempt++ {
		fmt.Fprintf(out, "\nChoose a template [1-%d] (default: 1): ", len(profiles))
		line, err := in.ReadString('\n')
		// A closed input still yields whatever was typed before EOF, so only bail out when there
		// is nothing left to interpret.
		if err != nil && strings.TrimSpace(line) == "" {
			return profiles[0], nil
		}

		answer := strings.TrimSpace(line)
		if answer == "" {
			return profiles[0], nil
		}
		if n, convErr := strconv.Atoi(answer); convErr == nil {
			if n >= 1 && n <= len(profiles) {
				return profiles[n-1], nil
			}
			fmt.Fprintf(out, "There is no template %d.\n", n)
			continue
		}
		if p, findErr := findProfile(profiles, answer); findErr == nil {
			return p, nil
		}
		fmt.Fprintf(out, "There is no template named %q.\n", answer)
	}
	return profile{}, fmt.Errorf("no valid template chosen after %d attempts", maxPromptAttempts)
}

// confirmOverwrite guards an existing config against being silently replaced once init is
// something you re-run to switch templates. Only asks a human: with no terminal attached it
// overwrites as it always has, so existing scripts are unaffected.
func confirmOverwrite(configPath string, in *bufio.Reader, out io.Writer) bool {
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		return true
	}
	if !isInteractive() {
		return true
	}
	fmt.Fprintf(out, "./%s already exists. Overwrite? [y/N]: ", configPath)
	line, err := in.ReadString('\n')
	if err != nil && strings.TrimSpace(line) == "" {
		return false
	}
	answer := strings.ToLower(strings.TrimSpace(line))
	return answer == "y" || answer == "yes"
}

func printProfiles(profiles []profile, out io.Writer) {
	fmt.Fprintln(out, "Available config templates:")
	fmt.Fprintln(out)
	width := 0
	for _, p := range profiles {
		if len(p.name) > width {
			width = len(p.name)
		}
	}
	for i, p := range profiles {
		fmt.Fprintf(out, "  %d) %-*s  %s\n", i+1, width, p.name, p.description)
	}
}

func findProfile(profiles []profile, name string) (profile, error) {
	for _, p := range profiles {
		if strings.EqualFold(p.name, name) {
			return p, nil
		}
	}
	names := make([]string, 0, len(profiles))
	for _, p := range profiles {
		names = append(names, p.name)
	}
	return profile{}, fmt.Errorf("unknown config template %q; available templates: %s", name, strings.Join(names, ", "))
}

// loadProfiles reads every bundled template, ordered with the default first so option 1 is always
// the conservative choice, then the rest alphabetically.
func loadProfiles() ([]profile, error) {
	entries, err := configProfiles.ReadDir(configProfileDir)
	if err != nil {
		return nil, err
	}
	profiles := make([]profile, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		raw, err := configProfiles.ReadFile(path.Join(configProfileDir, e.Name()))
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, profile{
			name:        profileName(e.Name()),
			description: parseDescription(raw),
			fileName:    e.Name(),
		})
	}
	sort.Slice(profiles, func(i, j int) bool {
		if (profiles[i].name == defaultProfile) != (profiles[j].name == defaultProfile) {
			return profiles[i].name == defaultProfile
		}
		return profiles[i].name < profiles[j].name
	})
	return profiles, nil
}

// profileName maps a file in configs/ to the name used by --profile:
// config.yml -> default, config-ARP.yaml -> ARP.
func profileName(fileName string) string {
	name := strings.TrimSuffix(strings.TrimSuffix(fileName, ".yaml"), ".yml")
	if !strings.HasPrefix(name, profileNamePrefix) {
		return defaultProfile
	}
	return strings.TrimPrefix(name, profileNamePrefix)
}

// parseDescription pulls the "# description: ..." line out of a template's leading comment block.
// It stops at the first line of actual YAML so a stray mention further down the file cannot be
// mistaken for the summary. A template without one simply has no description.
func parseDescription(raw []byte) string {
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if !strings.HasPrefix(trimmed, "#") {
			return "" // reached the YAML body; the leading comment block had no description
		}
		comment := strings.TrimSpace(strings.TrimPrefix(trimmed, "#"))
		if rest := strings.TrimPrefix(comment, descriptionMarker); rest != comment {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// The chosen template is always written as config.yml, since that is what `mykmyk scan` looks for
// locally and under ~/.config/mykmyk. The name in configs/ selects the template, not the output.
func creatLocalConfig(cfg []byte) error {
	err := os.WriteFile(api.DefaultConfigName, cfg, 0664)
	if err != nil {
		return err
	}

	return nil
}

func createGlobalConfig(cfg []byte) error {
	homeDirectory := os.Getenv("HOME")
	configPath := fmt.Sprintf("%s/.config/mykmyk", homeDirectory)
	if _, err := os.Stat(configPath); errors.Is(err, os.ErrNotExist) {
		err := os.MkdirAll(configPath, os.ModePerm)
		if err != nil {
			return err
		}
	}

	pathToConfigFile := fmt.Sprintf("%s/%s", configPath, api.DefaultConfigName)
	if _, err := os.Stat(pathToConfigFile); errors.Is(err, os.ErrNotExist) {
		err := os.WriteFile(pathToConfigFile, cfg, 0664)
		if err != nil {
			return err
		}
	}
	return nil
}
