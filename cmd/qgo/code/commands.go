// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

const (
	serviceTypeGin  = "gin"
	serviceTypeGRPC = "grpc"
)

type newCommand struct {
	app *App
}

// newServiceCommand binds a concrete service type to the shared scaffold flow.
type newServiceCommand struct {
	app         *App
	serviceType string
	options     *scaffoldOptions
}

// newNewCommand creates the parent `new` command.
func newNewCommand(app *App) Command {
	return &newCommand{app: app}
}

// newServiceGeneratorCommand creates a generator command for a specific service type.
func newServiceGeneratorCommand(app *App, serviceType string) Command {
	return &newServiceCommand{
		app:         app,
		serviceType: serviceType,
		options:     &scaffoldOptions{},
	}
}

// Cobra converts the logical `new` command into a Cobra command with subcommands.
func (command *newCommand) Cobra() *cobra.Command {
	newCmd := &cobra.Command{
		Use:   "new",
		Short: "Create a new GoForge service",
	}

	newCmd.AddCommand(newServiceGeneratorCommand(command.app, serviceTypeGin).Cobra())
	newCmd.AddCommand(newServiceGeneratorCommand(command.app, serviceTypeGRPC).Cobra())
	return newCmd
}

// Cobra creates the executable Cobra command that resolves options and scaffolds the service.
func (command *newServiceCommand) Cobra() *cobra.Command {
	cobraCmd := &cobra.Command{
		Use:   command.serviceType,
		Short: fmt.Sprintf("Create a new %s service", strings.ToUpper(command.serviceType)),
		RunE: func(cmd *cobra.Command, args []string) error {
			defaultGoVersion := strings.TrimSpace(command.options.goVersion)
			if defaultGoVersion == "" {
				var err error
				defaultGoVersion, err = command.app.installedGoVersion()
				if err != nil {
					return fmt.Errorf("detect installed Go version: %w", err)
				}
			}

			resolvedOptions, err := resolveScaffoldOptions(command.app.streams, command.options, defaultGoVersion)
			if err != nil {
				return err
			}

			scaffolder := newScaffolder(command.app.streams, command.app.runner)
			return scaffolder.createService(command.serviceType, resolvedOptions)
		},
	}

	cobraCmd.Flags().StringVarP(&command.options.modulePath, "module", "m", "", "Go module/package name for the new service")
	cobraCmd.Flags().StringVarP(&command.options.appName, "app-name", "a", "", "Value for app.name in application config")
	cobraCmd.Flags().StringVarP(&command.options.configFormat, "config-format", "c", "", "Configuration format: yaml or json")
	cobraCmd.Flags().StringVarP(&command.options.goVersion, "go-version", "g", "", "Go version for the generated module")
	cobraCmd.Flags().StringVarP(&command.options.outputDir, "dir", "d", "", "Output directory for the generated service")
	return cobraCmd
}
