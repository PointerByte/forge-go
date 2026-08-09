// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

// Package main exposes the qgo CLI entrypoint.
package main

import (
	"fmt"
	"os"

	"github.com/PointerByte/forge-go/cmd/qgo/code"
)

var (
	newAppFn      = code.NewApp
	executeAppFn  = executeApp
	writeErrorFn  = writeError
	exitProcessFn = os.Exit
)

func main() {
	if err := executeAppFn(newAppFn()); err != nil {
		writeErrorFn(err.Error())
		exitProcessFn(1)
	}
}

// executeApp runs the initialized CLI application.
func executeApp(app *code.App) error {
	return app.Execute()
}

// writeError sends a user-facing error message to standard error.
func writeError(message string) {
	fmt.Fprintln(os.Stderr, message)
}
