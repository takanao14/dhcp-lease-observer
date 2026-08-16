// Package app wires the command-line interface to one collector attempt.
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/takanao14/dhcp-lease-observer/internal/collector"
	"github.com/takanao14/dhcp-lease-observer/internal/config"
	"github.com/takanao14/dhcp-lease-observer/internal/identity"
	transport "github.com/takanao14/dhcp-lease-observer/internal/transport/ix2106"
)

const (
	ExitSuccess = 0
	ExitFailure = 1
	ExitUsage   = 2
)

func Run(args []string, stdout, stderr io.Writer, version string) int {
	flags := flag.NewFlagSet("dhcp-lease-observer", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", "/etc/dhcp-lease-observer/config.json", "collector configuration file")
	credentialsDirectory := flags.String("credentials-dir", "", "systemd credential directory")
	checkConfig := flags.Bool("check-config", false, "validate configuration and exit")
	showVersion := flags.Bool("version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		return ExitUsage
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return ExitUsage
	}
	if *showVersion {
		fmt.Fprintln(stdout, version)
		return ExitSuccess
	}
	loadedConfig, err := config.Load(*configPath)
	if err != nil {
		fmt.Fprintln(stderr, "configuration is invalid or unreadable")
		return ExitUsage
	}
	if *checkConfig {
		fmt.Fprintln(stdout, "configuration valid")
		return ExitSuccess
	}
	if !filepath.IsAbs(*credentialsDirectory) || filepath.Clean(*credentialsDirectory) != *credentialsDirectory {
		fmt.Fprintln(stderr, "credentials directory must be an absolute clean path")
		return ExitUsage
	}
	credentials, err := config.LoadCredentials(*credentialsDirectory)
	if err != nil {
		fmt.Fprintln(stderr, "credentials are invalid or unreadable")
		return ExitUsage
	}
	defer credentials.Clear()
	generator, err := identity.NewGenerator(credentials.IdentityKey)
	if err != nil {
		fmt.Fprintln(stderr, "identity key is invalid")
		return ExitUsage
	}
	defer generator.Clear()

	ctx, cancel := context.WithTimeout(context.Background(), loadedConfig.CollectionTimeout())
	defer cancel()
	runner := collector.Runner{
		Source: collector.SourceFunc(func(ctx context.Context) (transport.CommandBodies, error) {
			return transport.Collect(ctx, loadedConfig.Transport(), credentials.Password)
		}),
		Identity:       generator,
		StatePath:      loadedConfig.StatePath,
		PrometheusPath: loadedConfig.PrometheusPath,
		SourceInstance: loadedConfig.SourceInstance,
		Scope:          loadedConfig.Scope,
		Events:         stdout,
		Now:            time.Now,
	}
	if _, err := runner.Run(ctx); err != nil {
		var failure *collector.Failure
		if errors.As(err, &failure) {
			fmt.Fprintf(stderr, "collection failed: %s\n", failure.Kind())
		} else {
			fmt.Fprintln(stderr, "collection failed")
		}
		return ExitFailure
	}
	return ExitSuccess
}

func Main(args []string, version string) int {
	return Run(args, os.Stdout, os.Stderr, version)
}
