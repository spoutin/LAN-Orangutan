// Package cli implements the command-line interface
package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/spoutin/LAN-Orangutan/internal/config"
)

func cmdOut(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.OutOrStdout()
	}
	return os.Stdout
}

func cmdErr(cmd *cobra.Command) io.Writer {
	if cmd != nil {
		return cmd.ErrOrStderr()
	}
	return os.Stderr
}

var (
	cfgFile string
	cfg     *config.Config
)

// rootCmd represents the base command
var rootCmd = &cobra.Command{
	Use:   "orangutan",
	Short: "LAN Orangutan - Network Discovery Tool",
	Long: `LAN Orangutan is a network discovery and monitoring tool.
It scans your local network to find devices and provides
a web interface for viewing and managing discovered devices.`,

	// Execute prints errors itself; without this cobra prints them a second
	// time.
	SilenceErrors: true,

	// Flags have parsed by the time this runs, so anything that fails from here
	// is a runtime problem rather than a usage mistake. Silencing usage now
	// keeps a real error visible instead of burying it under the flag listing,
	// while a genuine flag mistake still gets the full help.
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		if cmd.Name() == "version" || cmd.Name() == "help" {
			return nil
		}
		return loadConfig()
	},
}

// Execute adds all child commands and runs the CLI
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", config.GetDefaultConfigFile(), "config file path")

	// Add subcommands
	rootCmd.AddCommand(scanCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(networksCmd)
	rootCmd.AddCommand(exportCmd)
	rootCmd.AddCommand(configCmd)
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(versionCmd)
}

func loadConfig() error {
	var err error
	cfg, err = config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("error loading config: %w", err)
	}

	// Environment variables override the file, so containers can be configured
	// without mounting one.
	if err := cfg.ApplyEnv(); err != nil {
		return fmt.Errorf("error applying environment configuration: %w", err)
	}
	return nil
}
