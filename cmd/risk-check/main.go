package main

import (
	"context"
	"os"
	"risk-check/internal/assessrisk"

	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd(assessrisk.AssessRisk).Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd builds the risk-check command. assessRisk is injected so tests
// can substitute a fake in place of the real (network-calling) AssessRisk.
func newRootCmd(assessRisk func(ctx context.Context, owner, packageName string, skipScan bool)) *cobra.Command {
	var noScan bool

	// cobra is lightweight go CLI framework, used here to parse command line arguments and flags
	rootCmd := &cobra.Command{
		Use:   "risk-check <owner> <package-name>",
		Short: "Assess risk before downloading a package",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			owner := args[0]
			packageName := args[1]
			assessRisk(context.Background(), owner, packageName, noScan)
			return nil
		},
	}

	rootCmd.Flags().BoolVar(&noScan, "no-scan", false, "skip the sandboxed download+scan; GitHub metadata only")

	return rootCmd
}
