// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"io"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

// IOStreams groups the standard input, output, and error streams used by the CLI.
type IOStreams struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

// Command defines an executable CLI command that can be converted into a Cobra command.
type Command interface {
	Cobra() *cobra.Command
}

// App wires the qgo CLI, its command tree, and the dependencies required to scaffold services.
type App struct {
	streams           IOStreams
	runner            goRunner
	goVersionResolver goVersionResolver
	introAnimator     introAnimator
	terminalDetector  terminalDetector
}

// goRunner abstracts `go` command execution so scaffolding behavior can be tested.
type goRunner func(dir string, args ...string) error

// goVersionResolver detects the installed Go version used as the default for generated modules.
type goVersionResolver func() (string, error)

// introAnimator renders the startup terminal animation.
type introAnimator func(io.Writer) error

// terminalDetector reports whether a writer points to an interactive terminal.
type terminalDetector func(io.Writer) bool

// NewApp creates the default qgo application ready to execute from main.
func NewApp() *App {
	return &App{
		streams: IOStreams{
			In:  os.Stdin,
			Out: os.Stdout,
			Err: os.Stderr,
		},
		runner: func(dir string, args ...string) error {
			// The executable is the fixed "go" toolchain and exec.Command does
			// not use a shell; only scaffolder-controlled subcommands are passed.
			command := exec.Command("go", args...) // #nosec G204 -- fixed "go" binary, scaffolder-controlled args, no shell
			command.Dir = dir
			command.Stdout = os.Stdout
			command.Stderr = os.Stderr
			return command.Run()
		},
		goVersionResolver: detectInstalledGoVersion,
		introAnimator:     animateGoForgeIntro,
		terminalDetector:  isTerminalWriter,
	}
}

// maybeAnimateIntro renders the project intro only for interactive terminal output.
func (app *App) maybeAnimateIntro() error {
	if app.introAnimator == nil || app.terminalDetector == nil {
		return nil
	}
	if !app.terminalDetector(app.streams.Out) {
		return nil
	}
	return app.introAnimator(app.streams.Out)
}

// installedGoVersion returns the default Go version for a generated module.
func (app *App) installedGoVersion() (string, error) {
	if app.goVersionResolver == nil {
		return detectInstalledGoVersion()
	}
	return app.goVersionResolver()
}

// detectInstalledGoVersion reads the active Go toolchain version from the installed go command.
func detectInstalledGoVersion() (string, error) {
	command := exec.Command("go", "env", "GOVERSION") // #nosec G204 -- fixed "go" binary and fixed args, no shell
	output, err := command.Output()
	if err != nil {
		return "", err
	}
	return normalizeGoVersion(string(output)), nil
}

// Execute runs the root qgo command tree.
func (app *App) Execute() error {
	return app.rootCommand().Execute()
}

// rootCommand builds the top-level Cobra command tree for qgo.
func (app *App) rootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "qgo",
		Short:         "GoForge service generator",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			return app.maybeAnimateIntro()
		},
	}
	root.AddCommand(newNewCommand(app).Cobra())
	return root
}
