///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - main_test.go
// Copyright (c) 2025-2026 Jeffrey H. Johnson
// Copyright (c) 2025-2026 The DPS8M Development Team
// SPDX-License-Identifier: MIT
// scspell-id: 97fee00e-6bd1-11f0-bbd3-80ee73e9b8e7
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
//
//nolint:godoclint,nolintlint
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"io"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

func TestSetupConsoleLogging(t *testing.T) { //nolint:paralleltest
	if enableGops {
		gopsClose()
	}

	defer goleak.VerifyNone(t)

	tmpDir := t.TempDir()
	logDir = tmpDir
	consoleLog = "noquiet" //nolint:goconst,nolintlint
	noCompress = false
	compressAlgo = "gzip" //nolint:goconst,nolintlint

	logPerm = 0o644
	logDirPerm = 0o755

	originalOutput := log.Writer()

	log.SetOutput(io.Discard)

	defer log.SetOutput(originalOutput)

	defer func() {
		consoleLogMutex.Lock()

		if consoleLogFile != nil {
			err := consoleLogFile.Close()
			if err != nil {
				t.Errorf("Failed to close console log file: %v",
					err)
			}

			consoleLogFile = nil
		}

		consoleLogMutex.Unlock()
	}()

	now := time.Date(2025, 7, 25, 10, 0, 0, 0, time.UTC)
	rotateConsoleLogAt(now)

	logPath := getConsoleLogPath(now)

	_, err := os.Stat(logPath)
	if os.IsNotExist(err) {
		t.Fatalf("Log file was not created at %s",
			logPath)
	}

	log.Printf("Test message")

	err = consoleLogFile.Sync()
	if err != nil {
		t.Fatalf("Failed to sync log file: %v",
			err)
	}

	content, err := os.ReadFile(logPath) //nolint:gosec
	if err != nil {
		t.Fatalf("Failed to read log file: %v",
			err)
	}

	if !strings.Contains(string(content), "Test message") {
		t.Errorf("Log file does not contain the test message. Content:\r\n%s",
			string(content))
	}
}

func TestConsoleLogRollover(t *testing.T) { //nolint:paralleltest
	if enableGops {
		gopsClose()
	}

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
			err := consoleLogFile.Close()
			if err != nil {
				t.Errorf("Failed to close console log file: %v",
					err)
			}

			consoleLogFile = nil
		}

		consoleLogMutex.Unlock()
	}()

	day1 := time.Date(2025, 7, 25, 10, 0, 0, 0, time.UTC)
	rotateConsoleLogAt(day1)

	day1LogPath := getConsoleLogPath(day1)

	_, err := os.Stat(day1LogPath)
	if os.IsNotExist(err) {
		t.Fatalf("Log file for day 1 was not created at %s",
			day1LogPath)
	}

	log.Printf("Test message day 1")

	err = consoleLogFile.Sync()
	if err != nil {
		t.Fatalf("Failed to sync log file for day 1: %v",
			err)
	}

	day2 := day1.Add(24 * time.Hour)
	rotateConsoleLogAt(day2)

	day1CompressedLogPath := day1LogPath + ".gz"

	_, err = os.Stat(day1CompressedLogPath)
	if os.IsNotExist(err) {
		t.Fatalf("Compressed log file for day 1 was not created at %s",
			day1CompressedLogPath)
	}

	_, err = os.Stat(day1LogPath)
	if !os.IsNotExist(err) {
		t.Fatalf("Old log file for day 1 was not removed after compression from %s",
			day1LogPath)
	}

	day2LogPath := getConsoleLogPath(day2)

	_, err = os.Stat(day2LogPath)
	if os.IsNotExist(err) {
		t.Fatalf("Log file for day 2 was not created at %s",
			day2LogPath)
	}

	log.Printf("Test message day 2")

	err = consoleLogFile.Sync()
	if err != nil {
		t.Fatalf("Failed to sync log file for day 2: %v",
			err)
	}

	content, err := os.ReadFile(day2LogPath) //nolint:gosec
	if err != nil {
		t.Fatalf("Failed to read day 2 log file: %v",
			err)
	}

	if !strings.Contains(string(content), "Test message day 2") {
		t.Errorf("Log file for day 2 does not contain the test message. Content:\r\n%s",
			string(content))
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Local Variables:
// mode: go
// tab-width: 4
// End:
///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
