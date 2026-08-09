// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestRenderGoForgeIntro(t *testing.T) {
	output := &bytes.Buffer{}

	if err := renderGoForgeIntro(output, 0, nil); err != nil {
		t.Fatalf("expected intro render without error, got %v", err)
	}

	if !strings.Contains(output.String(), "GoForge") {
		t.Fatalf("expected intro to contain GoForge, got %q", output.String())
	}
	if !strings.HasSuffix(output.String(), "\n") {
		t.Fatalf("expected intro to end with newline, got %q", output.String())
	}
}

func TestMaybeAnimateIntroRunsForTerminal(t *testing.T) {
	output := &bytes.Buffer{}
	called := false
	app := &App{
		streams: IOStreams{Out: output},
		introAnimator: func(writer io.Writer) error {
			called = true
			_, err := writer.Write([]byte("GoForge\n"))
			return err
		},
		terminalDetector: func(io.Writer) bool { return true },
	}

	if err := app.maybeAnimateIntro(); err != nil {
		t.Fatalf("expected intro animation without error, got %v", err)
	}
	if !called {
		t.Fatal("expected intro animator to run")
	}
	if !strings.Contains(output.String(), "GoForge") {
		t.Fatalf("expected intro output to contain GoForge, got %q", output.String())
	}
}

func TestMaybeAnimateIntroSkipsNonTerminal(t *testing.T) {
	called := false
	app := &App{
		streams:          IOStreams{Out: &bytes.Buffer{}},
		introAnimator:    func(io.Writer) error { called = true; return nil },
		terminalDetector: func(io.Writer) bool { return false },
	}

	if err := app.maybeAnimateIntro(); err != nil {
		t.Fatalf("expected skipped intro without error, got %v", err)
	}
	if called {
		t.Fatal("expected intro animator not to run for non-terminal output")
	}
}

func TestMaybeAnimateIntroReturnsAnimatorError(t *testing.T) {
	wantErr := errors.New("animation")
	app := &App{
		streams:          IOStreams{Out: &bytes.Buffer{}},
		introAnimator:    func(io.Writer) error { return wantErr },
		terminalDetector: func(io.Writer) bool { return true },
	}

	if err := app.maybeAnimateIntro(); !errors.Is(err, wantErr) {
		t.Fatalf("expected intro animator error %v, got %v", wantErr, err)
	}
}

func TestIsTerminalWriterRejectsBuffers(t *testing.T) {
	if isTerminalWriter(&bytes.Buffer{}) {
		t.Fatal("expected bytes.Buffer not to be detected as terminal")
	}
}
