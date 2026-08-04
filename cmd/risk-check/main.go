package main

import (
	"context"
	"fmt"
	"os"
	"risk-check/internal/assessrisk"

	"github.com/spf13/cobra"
)

func main() {
	var noScan bool

	var rootCmd = &cobra.Command{
		Use:   "risk-check",
		Short: "Assess risk before downloading a package",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 3 {
				fmt.Println("Usage: risk-check <owner> <package-name> [--no-scan]")
				os.Exit(1)
			}
			owner := args[1]
			packageName := args[2]
			assessrisk.AssessRisk(context.Background(), owner, packageName, noScan)
		},
	}

	rootCmd.Flags().BoolVar(&noScan, "no-scan", false, "skip the sandboxed download+scan; GitHub metadata only")

	rootCmd.Execute()
}
