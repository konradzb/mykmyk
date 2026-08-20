package cmd

import (
	"fmt"
	"os"

	"github.com/kosmosec/mykmyk/internal/api"
	"github.com/kosmosec/mykmyk/internal/preflight"
	"github.com/kosmosec/mykmyk/internal/scanner"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v2"
)

func NewScan() *cobra.Command {
	var skipCheck bool

	newScan := cobra.Command{
		Use:   "scan",
		Short: "Scan targets",
		Long:  "",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfgPath, err := cmd.Flags().GetString("config")
			if err != nil {
				return err
			}
			cfg, err := applyConfig(cfgPath)
			if err != nil {
				return err
			}
			// Preflight before touching the network: a missing tool or wordlist would otherwise fail
			// on every host and waste the whole run. --skip-check restores the old start-anyway path.
			if !skipCheck {
				result := preflight.New().Check(cfg)
				if len(result.Findings) > 0 {
					printReport(os.Stdout, cfg, result)
				}
				if !result.OK() {
					cmd.SilenceUsage = true
					cmd.SilenceErrors = true
					return fmt.Errorf("preflight found problems; fix them or re-run with --skip-check")
				}
			}
			err = scanner.Scan(cmd.Context(), cfg)
			if err != nil {
				return err
			}
			return nil
		},
	}

	newScan.Flags().BoolVar(&skipCheck, "skip-check", false, "Skip the pre-scan dependency check")

	return &newScan
}

func applyConfig(cfgPath string) (api.Config, error) {
	var cfg api.Config
	if cfgPath == "" {
		currentDir := os.Getenv("PWD")
		if currentDir == "" {
			return api.Config{}, errors.Errorf("No PWD in the ENV.")
		}
		cfgPath = fmt.Sprintf("%s/%s", currentDir, api.DefaultConfigName)
		if _, err := os.Stat(cfgPath); err != nil {
			homeDirectory := os.Getenv("HOME")
			if homeDirectory == "" {
				return api.Config{}, errors.Errorf("No HOME in the ENV.")
			}
			cfgPath = fmt.Sprintf("%s/.config/mykmyk/%s", homeDirectory, api.DefaultConfigName)
		}
	}

	rawCfg, err := os.ReadFile(cfgPath)
	if err != nil {
		return api.Config{}, err
	}
	err = yaml.Unmarshal(rawCfg, &cfg)
	if err != nil {
		return api.Config{}, err
	}
	return cfg, nil
}
