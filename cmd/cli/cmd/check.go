package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/kosmosec/mykmyk/internal/api"
	"github.com/kosmosec/mykmyk/internal/preflight"
	"github.com/spf13/cobra"
)

func NewCheck() *cobra.Command {
	return &cobra.Command{
		Use:   "check",
		Short: "Verify the tools and files the current config needs",
		Long: "Check reads the active config and, for every active task, verifies its tool is installed,\n" +
			"is the expected implementation, and that every file it references exists. It prints what is\n" +
			"missing and how to fix it, and changes nothing. Exits non-zero if anything is wrong.",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, err := cmd.Flags().GetString("config")
			if err != nil {
				return err
			}
			cfg, err := applyConfig(cfgPath)
			if err != nil {
				return err
			}
			result := preflight.New().Check(cfg)
			printReport(os.Stdout, cfg, result)
			if !result.OK() {
				// Non-zero exit so scripts and the scan preflight can gate on it. Silence cobra's own
				// error/usage output so the report is the only thing printed.
				cmd.SilenceUsage = true
				cmd.SilenceErrors = true
				return fmt.Errorf("check found problems that will break the scan")
			}
			return nil
		},
	}
}

// printReport writes one line per active task - ok, or a problem with the fix under it - followed by
// a count. Shared with scan so its abort report reads identically to `mykmyk check`.
func printReport(w io.Writer, cfg api.Config, result preflight.Result) {
	byTask := make(map[string][]preflight.Finding)
	for _, f := range result.Findings {
		byTask[f.Task] = append(byTask[f.Task], f)
	}

	problems := 0
	ok := 0
	for _, t := range cfg.Workflow.Tasks {
		if !t.Active {
			continue
		}
		found := byTask[t.Name]
		if len(found) == 0 {
			fmt.Fprintf(w, "[+] ok    %s (%s)\n", t.Name, t.Type)
			ok++
			continue
		}
		for _, f := range found {
			marker := "[~] warn "
			if f.Severity == preflight.Error {
				marker = "[!] FAIL "
				problems++
			}
			fmt.Fprintf(w, "%s %s (%s): %s\n", marker, t.Name, t.Type, f.Message)
			if f.Fix != "" {
				fmt.Fprintf(w, "          fix: %s\n", f.Fix)
			}
		}
	}
	fmt.Fprintf(w, "\n%d ok, %d problem(s)\n", ok, problems)
}
