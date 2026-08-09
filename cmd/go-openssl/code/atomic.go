// Copyright 2026 PointerByte Contributors
// SPDX-License-Identifier: Apache-2.0

package code

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

const maximumAtomicOriginalBytes = 16 * 1024 * 1024

type stagedPEMFile struct {
	update          pemFileUpdate
	tempPath        string
	originalContent []byte
	originalMode    os.FileMode
	originalInfo    os.FileInfo
	existed         bool
	committed       bool
}

// writePEMFilesAtomically stages a complete batch before replacing any target.
// Each rename is atomic. If a later commit step reports an error, earlier
// replacements are rolled back from verified in-memory snapshots.
func writePEMFilesAtomically(updates []pemFileUpdate) error {
	return writePEMFilesAtomicallyWithSync(updates, syncUpdateDirectories)
}

func writePEMFilesAtomicallyWithSync(
	updates []pemFileUpdate,
	syncFn func([]stagedPEMFile) error,
) error {
	if len(updates) == 0 {
		return nil
	}
	defer func() {
		for index := range updates {
			clear(updates[index].content)
		}
	}()

	staged := make([]stagedPEMFile, 0, len(updates))
	defer func() {
		clearStagedPEMFileBytes(staged)
	}()
	seenPaths := make(map[string]struct{}, len(updates))
	for _, update := range updates {
		cleanPath, err := validateAtomicTarget(update.path, seenPaths)
		if err != nil {
			cleanupStagedPEMFiles(staged)
			return err
		}
		update.path = cleanPath

		file := stagedPEMFile{update: update}
		info, err := os.Lstat(cleanPath)
		switch {
		case err == nil:
			if !info.Mode().IsRegular() {
				cleanupStagedPEMFiles(staged)
				return fmt.Errorf("atomic target %q is not a regular file", cleanPath)
			}
			file.existed = true
			file.originalContent, file.originalInfo, err = snapshotExistingFile(cleanPath, info)
			if err != nil {
				clear(file.originalContent)
				cleanupStagedPEMFiles(staged)
				return fmt.Errorf("snapshot existing target %q: %w", cleanPath, err)
			}
			file.originalMode = file.originalInfo.Mode().Perm()
		case errors.Is(err, os.ErrNotExist):
		default:
			cleanupStagedPEMFiles(staged)
			return fmt.Errorf("inspect atomic target %q: %w", cleanPath, err)
		}

		file.tempPath, err = stagePEMContent(cleanPath, update.content, update.mode)
		if err != nil {
			clear(file.originalContent)
			cleanupStagedPEMFiles(append(staged, file))
			return fmt.Errorf("stage %q: %w", cleanPath, err)
		}
		staged = append(staged, file)
	}

	if err := validateStagedTargetsUnchanged(staged); err != nil {
		cleanupStagedPEMFiles(staged)
		return err
	}

	for index := range staged {
		if err := os.Rename(staged[index].tempPath, staged[index].update.path); err != nil {
			rollbackErr := rollbackStagedPEMFiles(staged[:index])
			cleanupStagedPEMFiles(staged[index:])
			return errors.Join(
				fmt.Errorf("commit %q: %w", staged[index].update.path, err),
				rollbackErr,
			)
		}
		staged[index].tempPath = ""
		staged[index].committed = true
	}

	if err := syncFn(staged); err != nil {
		rollbackErr := rollbackStagedPEMFiles(staged)
		cleanupStagedPEMFiles(staged)
		return errors.Join(err, rollbackErr)
	}
	return nil
}

func validateAtomicTarget(path string, seenPaths map[string]struct{}) (string, error) {
	if path == "" {
		return "", fmt.Errorf("atomic target path is required")
	}
	cleanPath, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", fmt.Errorf("resolve atomic target %q: %w", path, err)
	}
	if _, exists := seenPaths[cleanPath]; exists {
		return "", fmt.Errorf("atomic target %q is duplicated", cleanPath)
	}
	seenPaths[cleanPath] = struct{}{}

	parentInfo, err := os.Stat(filepath.Dir(cleanPath))
	if err != nil {
		return "", fmt.Errorf("inspect parent for %q: %w", cleanPath, err)
	}
	if !parentInfo.IsDir() {
		return "", fmt.Errorf("parent for atomic target %q is not a directory", cleanPath)
	}
	return cleanPath, nil
}

func snapshotExistingFile(path string, expectedInfo os.FileInfo) (content []byte, info os.FileInfo, resultErr error) {
	source, err := os.Open(path) // #nosec G304 -- the validated regular target is intentionally snapshotted
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		resultErr = errors.Join(resultErr, source.Close())
	}()

	info, err = source.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(expectedInfo, info) {
		return nil, nil, fmt.Errorf("target changed while it was opened")
	}

	content, err = io.ReadAll(io.LimitReader(source, maximumAtomicOriginalBytes+1))
	if err != nil {
		return nil, nil, err
	}
	if len(content) > maximumAtomicOriginalBytes {
		clear(content)
		return nil, nil, fmt.Errorf("existing target exceeds %d bytes", maximumAtomicOriginalBytes)
	}
	return content, info, nil
}

func stagePEMContent(path string, content []byte, mode os.FileMode) (string, error) {
	return stagePEMReader(path, ".tmp-", bytes.NewReader(content), mode)
}

func stagePEMReader(path string, suffix string, content io.Reader, mode os.FileMode) (stagedPath string, resultErr error) {
	file, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+suffix)
	if err != nil {
		return "", err
	}
	stagedPath = file.Name()
	defer func() {
		closeErr := file.Close()
		if resultErr == nil && closeErr != nil {
			resultErr = closeErr
		}
		if resultErr != nil {
			_ = os.Remove(stagedPath)
			stagedPath = ""
		}
	}()

	if _, err := io.Copy(file, content); err != nil {
		return stagedPath, err
	}
	if err := file.Chmod(mode.Perm()); err != nil {
		return stagedPath, err
	}
	if err := file.Sync(); err != nil {
		return stagedPath, err
	}
	return stagedPath, nil
}

func rollbackStagedPEMFiles(staged []stagedPEMFile) error {
	var rollbackErr error
	for index := len(staged) - 1; index >= 0; index-- {
		file := &staged[index]
		if !file.committed {
			continue
		}

		if file.existed {
			restorePath, err := stagePEMContent(file.update.path, file.originalContent, 0o600)
			if err != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("stage restore for %q: %w", file.update.path, err))
				continue
			}
			if err := os.Rename(restorePath, file.update.path); err != nil {
				_ = os.Remove(restorePath)
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore %q: %w", file.update.path, err))
				continue
			}
			if err := os.Chmod(file.update.path, file.originalMode); err != nil {
				rollbackErr = errors.Join(rollbackErr, fmt.Errorf("restore permissions for %q: %w", file.update.path, err))
				continue
			}
		} else if err := os.Remove(file.update.path); err != nil && !errors.Is(err, os.ErrNotExist) {
			rollbackErr = errors.Join(rollbackErr, fmt.Errorf("remove replacement %q: %w", file.update.path, err))
			continue
		}
		file.committed = false
	}
	return errors.Join(rollbackErr, syncUpdateDirectories(staged))
}

func cleanupStagedPEMFiles(staged []stagedPEMFile) {
	for _, file := range staged {
		if file.tempPath != "" {
			_ = os.Remove(file.tempPath)
		}
	}
}

func validateStagedTargetsUnchanged(staged []stagedPEMFile) error {
	for index := range staged {
		file := &staged[index]
		info, err := os.Lstat(file.update.path)
		switch {
		case file.existed && err == nil:
			if !info.Mode().IsRegular() || !os.SameFile(file.originalInfo, info) {
				return fmt.Errorf("atomic target %q changed before commit", file.update.path)
			}
			currentContent, currentInfo, snapshotErr := snapshotExistingFile(file.update.path, info)
			if snapshotErr != nil {
				clear(currentContent)
				return fmt.Errorf("verify atomic target %q: %w", file.update.path, snapshotErr)
			}
			unchanged := currentInfo.Mode().Perm() == file.originalMode &&
				bytes.Equal(currentContent, file.originalContent)
			clear(currentContent)
			if !unchanged {
				return fmt.Errorf("atomic target %q changed before commit", file.update.path)
			}
		case file.existed:
			return fmt.Errorf("inspect atomic target %q before commit: %w", file.update.path, err)
		case err == nil:
			return fmt.Errorf("atomic target %q appeared before commit", file.update.path)
		case !errors.Is(err, os.ErrNotExist):
			return fmt.Errorf("inspect atomic target %q before commit: %w", file.update.path, err)
		}
	}
	return nil
}

func clearStagedPEMFileBytes(staged []stagedPEMFile) {
	for index := range staged {
		clear(staged[index].originalContent)
		clear(staged[index].update.content)
	}
}

func syncUpdateDirectories(staged []stagedPEMFile) error {
	seen := make(map[string]struct{}, len(staged))
	for _, file := range staged {
		directory := filepath.Dir(file.update.path)
		if _, exists := seen[directory]; exists {
			continue
		}
		seen[directory] = struct{}{}

		handle, err := os.Open(directory) // #nosec G304 -- target parents were validated by the atomic writer
		if err != nil {
			return fmt.Errorf("open output directory %q: %w", directory, err)
		}
		syncErr := handle.Sync()
		closeErr := handle.Close()
		if syncErr != nil {
			return errors.Join(fmt.Errorf("sync output directory %q: %w", directory, syncErr), closeErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close output directory %q: %w", directory, closeErr)
		}
	}
	return nil
}
