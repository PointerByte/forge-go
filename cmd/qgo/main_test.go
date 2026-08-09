// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/PointerByte/forge-go/cmd/qgo/code"
)

func TestMainSuccess(t *testing.T) {
	origNewApp := newAppFn
	origExecute := executeAppFn
	origWrite := writeErrorFn
	origExit := exitProcessFn
	t.Cleanup(func() {
		newAppFn = origNewApp
		executeAppFn = origExecute
		writeErrorFn = origWrite
		exitProcessFn = origExit
	})

	executed := false
	newAppFn = func() *code.App { return &code.App{} }
	executeAppFn = func(app *code.App) error {
		executed = true
		return nil
	}
	writeErrorFn = func(string) { t.Fatal("writeErrorFn should not be called") }
	exitProcessFn = func(int) { t.Fatal("exitProcessFn should not be called") }

	main()

	if !executed {
		t.Fatal("expected executeAppFn to be called")
	}
}

func TestMainError(t *testing.T) {
	origNewApp := newAppFn
	origExecute := executeAppFn
	origWrite := writeErrorFn
	origExit := exitProcessFn
	t.Cleanup(func() {
		newAppFn = origNewApp
		executeAppFn = origExecute
		writeErrorFn = origWrite
		exitProcessFn = origExit
	})

	wantErr := errors.New("boom")
	var gotMessage string
	var gotExitCode int

	newAppFn = func() *code.App { return &code.App{} }
	executeAppFn = func(app *code.App) error { return wantErr }
	writeErrorFn = func(message string) { gotMessage = message }
	exitProcessFn = func(code int) { gotExitCode = code }

	main()

	if gotMessage != wantErr.Error() {
		t.Fatalf("expected error message %q, got %q", wantErr.Error(), gotMessage)
	}
	if gotExitCode != 1 {
		t.Fatalf("expected exit code 1, got %d", gotExitCode)
	}
}

func TestExecuteApp(t *testing.T) {
	originalArgs := os.Args
	t.Cleanup(func() {
		os.Args = originalArgs
	})

	os.Args = []string{"qgo", "help"}
	app := &code.App{}
	if err := executeApp(app); err != nil {
		t.Fatalf("expected executeApp without error, got %v", err)
	}
}

func TestWriteError(t *testing.T) {
	originalStderr := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("expected pipe without error, got %v", err)
	}
	t.Cleanup(func() {
		os.Stderr = originalStderr
		reader.Close()
		writer.Close()
	})

	os.Stderr = writer
	writeError("boom")
	writer.Close()

	buffer := make([]byte, 64)
	n, err := reader.Read(buffer)
	if err != nil {
		t.Fatalf("expected read without error, got %v", err)
	}
	if !strings.Contains(string(buffer[:n]), "boom") {
		t.Fatalf("expected stderr to contain boom, got %q", string(buffer[:n]))
	}
}
