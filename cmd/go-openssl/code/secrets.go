// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const maximumSecretFileBytes = 64 * 1024

type secretSourceFlags struct {
	environment string
	file        string
}

func resolveSecretSource(label string, literal string, source secretSourceFlags) (string, error) {
	environment := strings.TrimSpace(source.environment)
	file := strings.TrimSpace(source.file)

	sourceCount := 0
	if literal != "" {
		sourceCount++
	}
	if environment != "" {
		sourceCount++
	}
	if file != "" {
		sourceCount++
	}
	if sourceCount > 1 {
		return "", fmt.Errorf("%s has multiple secret sources", label)
	}

	switch {
	case environment != "":
		secret, exists := os.LookupEnv(environment)
		if !exists {
			return "", fmt.Errorf("%s environment variable %q is not set", label, environment)
		}
		if secret == "" {
			return "", fmt.Errorf("%s environment variable %q is empty", label, environment)
		}
		return secret, nil
	case file != "":
		secret, err := readSecretFile(file)
		if err != nil {
			return "", fmt.Errorf("read %s file %q: %w", label, file, err)
		}
		if secret == "" {
			return "", fmt.Errorf("%s file %q is empty", label, file)
		}
		return secret, nil
	default:
		return literal, nil
	}
}

func readSecretFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("secret source is not a regular file")
	}

	file, err := os.Open(path) // #nosec G304 -- user-selected secret file is the intended CLI input
	if err != nil {
		return "", err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return "", fmt.Errorf("secret source changed while it was opened")
	}

	content, err := io.ReadAll(io.LimitReader(file, maximumSecretFileBytes+1))
	if err != nil {
		return "", err
	}
	defer clear(content)
	if len(content) > maximumSecretFileBytes {
		return "", fmt.Errorf("secret source exceeds %d bytes", maximumSecretFileBytes)
	}
	content = trimOneLineEnding(content)
	if len(content) == 0 {
		return "", errors.New("secret source is empty")
	}
	return string(content), nil
}

func trimOneLineEnding(content []byte) []byte {
	switch {
	case len(content) >= 2 && content[len(content)-2] == '\r' && content[len(content)-1] == '\n':
		return content[:len(content)-2]
	case len(content) >= 1 && content[len(content)-1] == '\n':
		return content[:len(content)-1]
	default:
		return content
	}
}
