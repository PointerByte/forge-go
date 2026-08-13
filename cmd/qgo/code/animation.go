// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"fmt"
	"io"
	"os"
	"time"
)

var goForgeIntroFrames = []string{
	"G",
	"Go",
	"GoF",
	"GoFo",
	"GoFor",
	"GoForg",
	"GoForge",
}

// animateGoForgeIntro renders the startup animation shown in interactive terminals.
func animateGoForgeIntro(output io.Writer) error {
	return renderGoForgeIntro(output, 35*time.Millisecond, time.Sleep)
}

// renderGoForgeIntro writes the animation frames. The sleep function is injected for tests.
func renderGoForgeIntro(output io.Writer, frameDelay time.Duration, sleep func(time.Duration)) error {
	for _, frame := range goForgeIntroFrames {
		if _, err := fmt.Fprintf(output, "\r%s", frame); err != nil {
			return err
		}
		if sleep != nil && frameDelay > 0 {
			sleep(frameDelay)
		}
	}
	_, err := fmt.Fprint(output, "\n")
	return err
}

// isTerminalWriter reports whether output is a real terminal instead of a pipe or buffer.
func isTerminalWriter(output io.Writer) bool {
	file, ok := output.(*os.File)
	if !ok {
		return false
	}

	info, err := file.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
