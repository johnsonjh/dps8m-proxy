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
	"fmt"
	"io"
	"log"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"go.uber.org/goleak"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

func TestSetupConsoleLogging(t *testing.T) { //nolint:paralleltest,tparallel,nolintlint
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

	content, err := os.ReadFile(logPath) //nolint:gosec,nolintlint
	if err != nil {
		t.Fatalf("Failed to read log file: %v",
			err)
	}

	if !strings.Contains(string(content), "Test message") {
		t.Errorf("Log file does not contain the test message. Content:\r\n%s",
			string(content))
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func TestConsoleLogRollover(t *testing.T) { //nolint:paralleltest,tparallel,nolintlint
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

	content, err := os.ReadFile(day2LogPath) //nolint:gosec,nolintlint
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

func TestFindCharmap(t *testing.T) { //nolint:paralleltest,tparallel,nolintlint
	if enableGops {
		gopsClose()
	}

	defer goleak.VerifyNone(t)

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"CodePage437", "CodePage437", "IBM Code Page 437"},       //nolint:goconst
		{"ISO8859-1", "ISO8859-1", "ISO 8859-1"},                  //nolint:goconst,nolintlint
		{"lowercase", "codepage437", "IBM Code Page 437"},         //nolint:goconst,nolintlint
		{"with spaces", "IBM Code Page 437", "IBM Code Page 437"}, //nolint:goconst,nolintlint
		{"dash and space", "ISO-8859 6E", "ISO-8859-6E"},          //nolint:goconst,nolintlint
		{"underscore and dash", "ISO_8859-6E", "ISO-8859-6E"},     //nolint:goconst,nolintlint
		{"cp space", "CP 1047", "IBM Code Page 1047"},
		{"cp no space", "CP1047", "IBM Code Page 1047"},
		{"codepage space", "CodePage 437", "IBM Code Page 437"},
		{"cp 437", "CP437", "IBM Code Page 437"},
		{"win space", "Win 1252", "Windows 1252"},
		{"win no space", "Win1252", "Windows 1252"},
		{"mac space", "Mac Cyrillic", "Macintosh Cyrillic"},
		{"mac no space", "MacCyrillic", "Macintosh Cyrillic"},
		{"mac exactly", "Mac", "Macintosh"},
		{"invalid", "NoSuchCharmap", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name,
			func(t *testing.T) {
				t.Parallel()

				cm := findCharmap(tt.input)
				if tt.expected == "" {
					if cm != nil {
						t.Errorf("findCharmap(%q) expected nil, got %v",
							tt.input, cm)
					}
				} else {
					if cm == nil {
						t.Errorf("findCharmap(%q) expected %q, got nil",
							tt.input, tt.expected)
					} else {
						got := fmt.Sprintf("%v",
							cm)
						if !strings.Contains(strings.ToLower(got), strings.ToLower(tt.expected)) {
							t.Errorf("findCharmap(%q) = %q, want it to contain %q",
								tt.input, got, tt.expected)
						}
					}
				}
			},
		)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func TestNaturalLess(t *testing.T) {
	t.Parallel()

	tests := []struct {
		s1       string
		s2       string
		expected bool
	}{
		{"ISO 8859-1", "ISO 8859-2", true},   //nolint:goconst,nolintlint
		{"ISO 8859-2", "ISO 8859-10", true},  //nolint:goconst,nolintlint
		{"ISO 8859-10", "ISO 8859-2", false}, //nolint:goconst,nolintlint
		{"CodePage437", "CodePage1047", true},
		{"CodePage1047", "CodePage437", false},
		{"a1", "a2", true},
		{"a2", "a10", true},
		{"a10", "a2", false},
		{"1", "2", true},
		{"2", "10", true},
		{"10", "2", false},
		{"abc", "abc", false}, //nolint:goconst,nolintlint
		{"abc", "abd", true},
		{"ISO 8859-6", "ISO-8859-6E", true},  //nolint:goconst,nolintlint
		{"ISO-8859-6E", "ISO 8859-7", true},  //nolint:goconst,nolintlint
		{"ISO-8859-6E", "ISO 8859-16", true}, //nolint:goconst,nolintlint
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%s_%s",
			tt.s1, tt.s2),
			func(t *testing.T) {
				t.Parallel()

				got := naturalLess(tt.s1, tt.s2)
				if got != tt.expected {
					t.Errorf("naturalLess(%q, %q) = %v, want %v",
						tt.s1, tt.s2, got, tt.expected)
				}
			},
		)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func TestNaturalSort(t *testing.T) {
	t.Parallel()

	input := []string{
		"ISO 8859-1",
		"ISO 8859-2",
		"ISO 8859-3",
		"ISO 8859-4",
		"ISO 8859-5",
		"ISO 8859-6",
		"ISO 8859-7",
		"ISO 8859-8",
		"ISO 8859-9",
		"ISO 8859-10",
		"ISO 8859-13",
		"ISO 8859-14",
		"ISO 8859-15",
		"ISO 8859-16",
		"ISO-8859-6E",
		"ISO-8859-6I",
		"ISO-8859-8E",
		"ISO-8859-8I",
	}

	expected := []string{
		"ISO 8859-1",
		"ISO 8859-2",
		"ISO 8859-3",
		"ISO 8859-4",
		"ISO 8859-5",
		"ISO 8859-6",
		"ISO-8859-6E",
		"ISO-8859-6I",
		"ISO 8859-7",
		"ISO 8859-8",
		"ISO-8859-8E",
		"ISO-8859-8I",
		"ISO 8859-9",
		"ISO 8859-10",
		"ISO 8859-13",
		"ISO 8859-14",
		"ISO 8859-15",
		"ISO 8859-16",
	}

	sort.Slice(input,
		func(i, j int) bool {
			return naturalLess(input[i], input[j])
		},
	)

	for i := range input {
		if input[i] != expected[i] {
			t.Errorf("at index %d: got %q, want %q", i, input[i], expected[i])
		}
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
