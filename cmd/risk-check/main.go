package main

import (
	"fmt"
	"os"
	"risk-check/internal/assessrisk"

	"github.com/spf13/cobra"
)

func main() {
	var rootCmd = &cobra.Command{
		Use:   "risk-check",
		Short: "Assess risk before downloading a package",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				fmt.Println("Usage: risk-check <package-name>")
				os.Exit(1)
			}
			packageName := args[0]
			assessrisk.AssessRisk(packageName)
		},
	}

	rootCmd.Execute()
}
