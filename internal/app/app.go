// Package app wires the command-line interface to one collector attempt.
package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/takanao14/dhcp-lease-observer/internal/collector"
	"github.com/takanao14/dhcp-lease-observer/internal/config"
	"github.com/takanao14/dhcp-lease-observer/internal/identity"
	"github.com/takanao14/dhcp-lease-observer/internal/output"
	transport "github.com/takanao14/dhcp-lease-observer/internal/transport/ix2106"
)

const sourceName = "ix2106_cli"

const (
	ExitSuccess = 0
	ExitFailure = 1
	ExitUsage   = 2
)

func Run(args []string, stdout, stderr io.Writer, version string) int {
	if err := validateOptionForm(args); err != nil {
		fmt.Fprintln(stderr, "invalid option form; use --long-option")
		return ExitUsage
	}
	flags := flag.NewFlagSet("dhcp-lease-observer", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Usage = func() {
		fmt.Fprintln(stderr, "Usage: dhcp-lease-observer [options]")
		fmt.Fprintln(stderr, "  --config PATH           collector configuration file")
		fmt.Fprintln(stderr, "  --credentials-dir PATH  systemd credential directory")
		fmt.Fprintln(stderr, "  --check-config          validate configuration and exit")
		fmt.Fprintln(stderr, "  --version               print version and exit")
		fmt.Fprintln(stderr, "  --help                  print this help and exit")
	}
	configPath := flags.String("config", "/etc/dhcp-lease-observer/config.json", "collector configuration file")
	credentialsDirectory := flags.String("credentials-dir", "", "systemd credential directory")
	checkConfig := flags.Bool("check-config", false, "validate configuration and exit")
	showVersion := flags.Bool("version", false, "print version and exit")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return ExitSuccess
		}
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
		writeStartupFailure(stdout, stderr, "", "", "configuration_invalid")
		return ExitUsage
	}
	if *checkConfig {
		fmt.Fprintln(stdout, "configuration valid")
		return ExitSuccess
	}
	if !filepath.IsAbs(*credentialsDirectory) || filepath.Clean(*credentialsDirectory) != *credentialsDirectory {
		writeStartupFailure(stdout, stderr, sourceName, loadedConfig.SourceInstance, "credentials_invalid")
		return ExitUsage
	}
	credentials, err := config.LoadCredentials(*credentialsDirectory)
	if err != nil {
		writeStartupFailure(stdout, stderr, sourceName, loadedConfig.SourceInstance, "credentials_invalid")
		return ExitUsage
	}
	defer credentials.Clear()
	generator, err := identity.NewGenerator(credentials.IdentityKey)
	if err != nil {
		writeStartupFailure(stdout, stderr, sourceName, loadedConfig.SourceInstance, "identity_key_invalid")
		return ExitUsage
	}
	defer generator.Clear()

	signalContext, stopSignals := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stopSignals()
	ctx, cancel := context.WithTimeout(signalContext, loadedConfig.CollectionTimeout())
	defer cancel()
	runner := collector.Runner{
		Source: collector.SourceFunc(func(ctx context.Context) (transport.CommandBodies, error) {
			return transport.Collect(ctx, loadedConfig.Transport(), credentials.Password)
		}),
		Identity:       generator,
		StatePath:      loadedConfig.StatePath,
		PrometheusPath: loadedConfig.PrometheusPath,
		SourceName:     sourceName,
		SourceInstance: loadedConfig.SourceInstance,
		Scope:          loadedConfig.Scope,
		Events:         stdout,
		Now:            time.Now,
	}
	if _, err := runner.Run(ctx); err != nil {
		var failure *collector.Failure
		if !errors.As(err, &failure) || failure.Kind() == "event_output_failed" {
			fmt.Fprintln(stderr, "collector log output failed")
		}
		return ExitFailure
	}
	return ExitSuccess
}

func validateOptionForm(args []string) error {
	for _, argument := range args {
		if argument == "--" {
			break
		}
		if argument == "-h" || !strings.HasPrefix(argument, "-") || strings.HasPrefix(argument, "--") {
			continue
		}
		return errors.New("single-hyphen long option")
	}
	return nil
}

func writeStartupFailure(stdout, stderr io.Writer, source, sourceInstance, failureClass string) {
	err := output.WriteStartupFailureEvent(stdout, output.StartupFailureEvent{
		SchemaVersion:  1,
		ObservedAt:     time.Now().UTC(),
		Event:          "collector_start_failed",
		Severity:       output.SeverityError,
		Source:         source,
		SourceInstance: sourceInstance,
		FailureClass:   failureClass,
		Retryable:      false,
	})
	if err != nil {
		fmt.Fprintln(stderr, "collector log output failed")
	}
}

func Main(args []string, version string) int {
	return Run(args, os.Stdout, os.Stderr, version)
}
