// Package preflight verifies that everything an active config needs is present before a scan runs.
//
// binary.Run already turns a missing tool into a loud error, but a missing wordlist, an unfetched
// nuclei template set, or the wrong "httpx" in PATH only surface mid-scan - as a per-host failure
// repeated for every live host, a whole run wasted before the operator notices. preflight moves that
// discovery to the front and, unlike the scan, changes nothing: it reads the config, checks tools and
// paths, and reports what to fix.
package preflight

import (
	"fmt"
	"os"
	"os/exec"
	"strings"

	"github.com/kosmosec/mykmyk/internal/api"
	"gopkg.in/yaml.v2"
)

type Severity int

const (
	// Warning is advisory: printed, but does not block a scan.
	Warning Severity = iota
	// Error blocks: the scan cannot succeed until it is fixed.
	Error
)

// Finding is one problem with one task. Fix is the exact action that resolves it, so the report can
// tell the operator what to do rather than only what is wrong.
type Finding struct {
	Task     string
	Type     api.TaskType
	Severity Severity
	Message  string
	Fix      string
}

// Result is every finding from one Check. A Result with no Error-severity finding is OK: warnings
// alone do not stop a scan.
type Result struct {
	Findings []Finding
}

func (r Result) OK() bool {
	for _, f := range r.Findings {
		if f.Severity == Error {
			return false
		}
	}
	return true
}

// Checker runs the checks. LookPath and Run are seams: the command wires them to the real os/exec
// functions via New, and tests inject fakes so a check can be exercised without the tools installed.
type Checker struct {
	LookPath func(string) (string, error)
	Run      func(bin string, args ...string) (string, error)
}

// New returns a Checker wired to the real environment.
func New() Checker {
	return Checker{
		LookPath: exec.LookPath,
		Run: func(bin string, args ...string) (string, error) {
			out, err := exec.Command(bin, args...).CombinedOutput()
			return string(out), err
		},
	}
}

// Check inspects every active task. Inactive tasks are skipped: they do not run, so their tools do
// not matter.
func (c Checker) Check(cfg api.Config) Result {
	var res Result
	for _, task := range cfg.Workflow.Tasks {
		if !task.Active {
			continue
		}
		res.Findings = append(res.Findings, c.checkTask(task)...)
	}
	return res
}

func (c Checker) checkTask(task api.Task) []Finding {
	var findings []Finding
	run := extractRun(task.Run)

	req, known := requirements[task.Type]
	binaryOK := true
	if known && req.binary != "" {
		path, err := c.LookPath(req.binary)
		if err != nil {
			binaryOK = false
			findings = append(findings, Finding{
				Task: task.Name, Type: task.Type, Severity: Error,
				Message: fmt.Sprintf("%s is not installed (not found in PATH)", req.binary),
				Fix:     installHint(req.binary),
			})
		} else if req.identity != nil {
			if err := req.identity(c, path); err != nil {
				findings = append(findings, Finding{
					Task: task.Name, Type: task.Type, Severity: Error,
					Message: err.Error(),
					Fix:     installHint(req.binary),
				})
			}
		}
	}

	// Every absolute path in a task's args, plus the filesystem task's input, must exist. One rule
	// covers ffuf -w, nuclei -t/-ud and any future tool's --flag /path without knowing the flag.
	for _, p := range referencedPaths(run) {
		if _, err := os.Stat(p); err != nil {
			findings = append(findings, Finding{
				Task: task.Name, Type: task.Type, Severity: Error,
				Message: fmt.Sprintf("required file or directory is missing: %s", p),
				Fix:     fmt.Sprintf("create %s, or point %s at a path that exists", p, task.Name),
			})
		}
	}

	// Type-specific checks that go beyond presence (e.g. nuclei's managed templates). Skipped when
	// the binary itself is missing - the missing-binary finding already says enough.
	if known && req.extra != nil && binaryOK {
		findings = append(findings, req.extra(c, task, run)...)
	}

	return findings
}

// runFields is the subset of any task's run block preflight needs. It is filled by round-tripping
// the config's interface{} run through yaml, the same decoupling trick each executor uses to read
// its own Task, so preflight does not import every executor package.
type runFields struct {
	Args  []string `yaml:"args,omitempty"`
	Input string   `yaml:"input,omitempty"`
}

func extractRun(in interface{}) runFields {
	var r runFields
	raw, err := yaml.Marshal(in)
	if err != nil {
		return r
	}
	_ = yaml.Unmarshal(raw, &r)
	return r
}

// referencedPaths lists the filesystem paths a task depends on. The filesystem input (usually
// ./hosts, relative to the pentest folder) is always a path; among args only absolute ones are
// treated as paths, so tool values like "-rl", "3" or "wordpress,dos" are not mistaken for files.
func referencedPaths(run runFields) []string {
	var paths []string
	if run.Input != "" {
		paths = append(paths, run.Input)
	}
	for _, a := range run.Args {
		if strings.HasPrefix(a, "/") {
			paths = append(paths, a)
		}
	}
	return paths
}
