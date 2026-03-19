package cmd

import (
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

const (
	defaultAPIURL = "http://localhost:8000"
)

type rootOptions struct {
	apiURL    string
	timeout   time.Duration
	token     string
	tokenFile string
}

func NewRootCmd() *cobra.Command {
	opts := &rootOptions{
		apiURL:    envOrDefault("AOF_API_URL", defaultAPIURL),
		timeout:   2 * time.Minute,
		token:     os.Getenv("AOF_TOKEN"),
		tokenFile: envOrDefault("AOF_TOKEN_FILE", defaultTokenFilePath()),
	}

	rootCmd := &cobra.Command{
		Use:           "aof",
		Short:         "AOF CLI for running supported security tools through FastAPI",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if cmd.Name() == "login" {
				return nil
			}
			if strings.TrimSpace(opts.token) != "" {
				return nil
			}

			stored, err := readStoredToken(opts.tokenFile)
			if err != nil {
				if os.IsNotExist(err) {
					return nil
				}
				return err
			}
			opts.token = strings.TrimSpace(stored.AccessToken)
			return nil
		},
	}

	rootCmd.PersistentFlags().StringVar(
		&opts.apiURL,
		"api-url",
		opts.apiURL,
		"FastAPI base URL, for example http://localhost:8000",
	)
	rootCmd.PersistentFlags().StringVar(
		&opts.token,
		"token",
		opts.token,
		"Bearer token for FastAPI authentication (or set AOF_TOKEN)",
	)
	rootCmd.PersistentFlags().DurationVar(
		&opts.timeout,
		"timeout",
		opts.timeout,
		"HTTP request timeout",
	)
	rootCmd.PersistentFlags().StringVar(
		&opts.tokenFile,
		"token-file",
		opts.tokenFile,
		"File path for cached login token",
	)

	rootCmd.AddCommand(newLoginCmd(opts))
	rootCmd.AddCommand(newSubfinderCmd(opts))
	return rootCmd
}

func envOrDefault(name string, fallback string) string {
	value := os.Getenv(name)
	if value == "" {
		return fallback
	}
	return value
}
