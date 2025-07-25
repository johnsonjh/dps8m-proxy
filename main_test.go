///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - main_test.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

func TestRotateConsoleLog(t *testing.T) { //nolint:paralleltest
	defer goleak.VerifyNone(t)

	tmpDir := t.TempDir()

	logDir = tmpDir
	consoleLog = "noquiet"
	noCompress = false
	compressAlgo = "gzip"
	logPerm = 0o644
	logDirPerm = 0o755

	originalOutput := log.Writer()
	log.SetOutput(io.Discard)

	defer log.SetOutput(originalOutput)

	defer func() {
		consoleLogMutex.Lock()

		if consoleLogFile != nil {
			if err := consoleLogFile.Close(); err != nil {
				t.Errorf("Failed to close console log file: %v",
					err)
			}
			consoleLogFile = nil
		}

		consoleLogMutex.Unlock()
		log.SetOutput(originalOutput)
	}()

	now := time.Date(2025, 7, 25, 10, 0, 0, 0, time.UTC)
	rotateConsoleLogAt(now)

	day1LogPath := getConsoleLogPath(now)
	if _, err := os.Stat(day1LogPath); os.IsNotExist(err) {
		t.Fatalf("Log file for day 1 was not created at %s",
			day1LogPath)
	}

	log.Printf("Test message day 1")
	if err := consoleLogFile.Sync(); err != nil {
		t.Fatalf("Failed to sync log file for day 1: %v",
			err)
	}

	tomorrow := now.Add(24 * time.Hour)
	rotateConsoleLogAt(tomorrow)

	day1CompressedLogPath := day1LogPath + ".gz"
	if _, err := os.Stat(day1CompressedLogPath); os.IsNotExist(err) {
		t.Fatalf("Compressed log file for day 1 was not created at %s",
			day1CompressedLogPath)
	}

	if _, err := os.Stat(day1LogPath); !os.IsNotExist(err) {
		t.Fatalf("Old log file for day 1 was not removed after compression from %s",
			day1LogPath)
	}

	day2LogPath := getConsoleLogPath(tomorrow)
	if _, err := os.Stat(day2LogPath); os.IsNotExist(err) {
		t.Fatalf("Log file for day 2 was not created at %s",
			day2LogPath)
	}

	log.Printf("Test message day 2")
	if err := consoleLogFile.Sync(); err != nil {
		t.Fatalf("Failed to sync log file for day 2: %v",
			err)
	}

	content, err := os.ReadFile(day2LogPath)
	if err != nil {
		t.Fatalf("Failed to read day 2 log file: %v",
			err)
	}

	if !filepath.IsAbs(day2LogPath) {
		absPath, _ := filepath.Abs(day2LogPath)
		t.Logf("Checking for 'Test message day 2' in %s",
			absPath)
	} else {
		t.Logf("Checking for 'Test message day 2' in %s",
			day2LogPath)
	}

	if !strings.Contains(string(content), "Test message day 2") {
		t.Errorf("Log file for day 2 does not contain the test message. Content:\r\n%s",
			string(content))
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
