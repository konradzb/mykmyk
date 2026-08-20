package preflight

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/kosmosec/mykmyk/internal/api"
)

// spec is what preflight needs to know about one task type: the binary it shells out to, an optional
// probe that confirms the binary is the right implementation, and an optional extra check for data
// the tool needs beyond its args. Adding a new tool means adding its executor as before and one line
// here; its data-path args are validated by the generic absolute-path rule for free.
type spec struct {
	binary   string
	identity func(c Checker, path string) error
	extra    func(c Checker, task api.Task, run runFields) []Finding
}

// requirements maps a task type to its external needs. nc, smb and rdp are pure Go and have no entry;
// exec runs an arbitrary user command and filesystem only reads a file, so neither has a fixed binary.
var requirements = map[api.TaskType]spec{
	api.NmapType:   {binary: "nmap"},
	api.HTTPXType:  {binary: "httpx", identity: projectDiscoveryProbe},
	api.NucleiType: {binary: "nuclei", extra: nucleiTemplatesCheck},
	api.FfufType:   {binary: "ffuf"},
	api.SSLScan:    {binary: "sslscan"},
}

// projectDiscoveryProbe distinguishes ProjectDiscovery's httpx from the other binaries that share the
// name (pip's httpx[cli], httprobe wrappers). The real one prints a banner naming projectdiscovery on
// `httpx -version`; the impostors either error or print something else. The exit code is ignored on
// purpose - the identifying string is what matters.
func projectDiscoveryProbe(c Checker, path string) error {
	out, _ := c.Run(path, "-version")
	if strings.Contains(strings.ToLower(out), "projectdiscovery") {
		return nil
	}
	return fmt.Errorf("the httpx in PATH is not ProjectDiscovery httpx (`httpx -version` did not identify it)")
}

// nucleiTemplatesCheck catches a nuclei task whose managed templates are not usable. It only fires
// for the default setup, where the config points nuclei at no template path of its own: then nuclei
// reads its managed directory, which exists only after `nuclei -update-templates`. When the config
// carries an explicit absolute path, the generic path-existence check already covers it, so this
// stays quiet to avoid reporting the same gap twice.
//
// It verifies the templates *directory* nuclei will actually read - not just that the config JSON
// exists. A run as root with templates only fetched for another user, or a config file left behind
// pointing at a directory that was since removed, both leave the JSON present but the directory gone;
// checking the JSON alone would pass while nuclei fails on every host.
func nucleiTemplatesCheck(c Checker, task api.Task, run runFields) []Finding {
	if hasAbsolutePath(run.Args) {
		return nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil
	}
	dir := nucleiTemplatesDir(home)
	if isNonEmptyDir(dir) {
		return nil
	}
	return []Finding{{
		Task: task.Name, Type: task.Type, Severity: Error,
		Message: fmt.Sprintf("nuclei templates are not installed (%s is missing or empty)", dir),
		Fix:     fmt.Sprintf("nuclei -update-templates   (as the user the scan runs as - templates live under that user's home, e.g. %s)", dir),
	}}
}

// nucleiTemplatesDir is the directory nuclei will read templates from: the one recorded in its config
// after a fetch, or its v3 default ($HOME/.local/nuclei-templates) when that config is absent.
func nucleiTemplatesDir(home string) string {
	config := filepath.Join(home, ".config", "nuclei", ".templates-config.json")
	if raw, err := os.ReadFile(config); err == nil {
		var cfg struct {
			Dir string `json:"nuclei-templates-directory"`
		}
		if json.Unmarshal(raw, &cfg) == nil && cfg.Dir != "" {
			return cfg.Dir
		}
	}
	return filepath.Join(home, ".local", "nuclei-templates")
}

func isNonEmptyDir(dir string) bool {
	entries, err := os.ReadDir(dir)
	return err == nil && len(entries) > 0
}

func hasAbsolutePath(args []string) bool {
	for _, a := range args {
		if strings.HasPrefix(a, "/") {
			return true
		}
	}
	return false
}

func installHint(binary string) string {
	switch binary {
	case "nmap":
		return "apt install nmap"
	case "sslscan":
		return "apt install sslscan"
	case "ffuf":
		return "apt install ffuf   (or: go install github.com/ffuf/ffuf/v2@latest)"
	case "httpx":
		return "go install github.com/projectdiscovery/httpx/cmd/httpx@latest   (ProjectDiscovery httpx)"
	case "nuclei":
		return "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
	default:
		return fmt.Sprintf("install %s and make sure it is in PATH", binary)
	}
}
