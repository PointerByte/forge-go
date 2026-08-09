// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"io"
	"os"

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

// App wires the go-openssl CLI, its command tree, and the certificate generator.
type App struct {
	streams   IOStreams
	generator *Generator
}

// NewApp creates the default go-openssl application ready to execute from main.
func NewApp() *App {
	return &App{
		streams: IOStreams{
			In:  os.Stdin,
			Out: os.Stdout,
			Err: os.Stderr,
		},
		generator: NewGenerator(),
	}
}

// Execute runs the root go-openssl command tree.
func (app *App) Execute() error {
	return app.rootCommand().Execute()
}

// rootCommand builds the top-level Cobra command tree for go-openssl.
func (app *App) rootCommand() *cobra.Command {
	root := &cobra.Command{
		Use:           "go-openssl",
		Short:         "Generate PEM certificates and keys for RSA, ECC, or Ed25519",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.SetIn(app.streams.In)
	root.SetOut(app.streams.Out)
	root.SetErr(app.streams.Err)
	root.AddCommand(newGenerateCommand(app).Cobra())
	root.AddCommand(newReadCommand(app).Cobra())
	root.AddCommand(newReencryptCommand(app).Cobra())
	return root
}
