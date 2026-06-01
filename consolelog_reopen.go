//go:build !windows && !wasm

///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - consolelog_reopen.go
// Copyright (c) 2025-2026 Jeffrey H. Johnson
// Copyright (c) 2025-2026 The DPS8M Development Team
// SPDX-License-Identifier: MIT
// scspell-id: 4c24063c-5dca-11f1-98e6-246e96298730
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
	"path/filepath"
	"sync/atomic"
	"time"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

var consoleLogReopening atomic.Bool

///////////////////////////////////////////////////////////////////////////////////////////////////

func reopenConsoleLog() {
	if !staticConsoleLog {
		return
	}

	consoleLogMutex.Lock()
	active := consoleLog != ""
	consoleLogMutex.Unlock()

	if !active {
		return
	}

	if consoleLogReopening.Load() {
		return // A retry loop already owns the reopen.
	}

	log.Printf("%sReopening static console log file.",
		bellPrefix())

	err := reopenConsoleLogOnce()
	if err == nil {
		return
	}

	reportConsoleLogReopenError(err)

	if !consoleLogReopening.CompareAndSwap(false, true) {
		return
	}

	go func() {
		defer consoleLogReopening.Store(false)
		defer recoverGoroutine("consoleLogReopen")

		reopenConsoleLogLoop()
	}()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func reopenConsoleLogOnce() error {
	consoleLogMutex.Lock()
	defer consoleLogMutex.Unlock()

	if consoleLog == "" {
		return nil
	}

	logPath := getConsoleLogPath(time.Now())

	err := os.MkdirAll(
		filepath.Dir(logPath), os.FileMode(logDirPerm), //nolint:gosec,nolintlint
	)
	if err != nil {
		return fmt.Errorf("creating console log directory: %w", err)
	}

	file, err := os.OpenFile( //nolint:gosec,nolintlint
		logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		os.FileMode(logPerm), //nolint:gosec,nolintlint
	)
	if err != nil {
		return fmt.Errorf("opening console log file: %w", err)
	}

	old := consoleLogFile
	consoleLogFile = file

	fileWriter := &emojiStripperWriter{w: consoleLogFile}

	if isConsoleLogQuiet.Load() {
		log.SetOutput(fileWriter)
	} else {
		log.SetOutput(io.MultiWriter(os.Stdout, fileWriter))
	}

	if old != nil {
		_ = old.Close()
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func reportConsoleLogReopenError(err error) {
	_, _ = fmt.Fprintf(os.Stdout,
		"%s %sERROR: Failed to reopen console log file (retrying every 10s): %v\r\n",
		nowStamp(), warnPrefix(), err)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func reopenConsoleLogLoop() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-shutdownSignal:
			return

		case <-ticker.C:
			err := reopenConsoleLogOnce()
			if err != nil {
				reportConsoleLogReopenError(err)

				continue
			}

			_, _ = fmt.Fprintf(os.Stdout,
				"%s %sConsole log file reopened successfully.\r\n",
				nowStamp(), alertPrefix())

			return
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Local Variables:
// mode: go
// tab-width: 4
// fill-column: 100
// eval: (setq-local display-fill-column-indicator-column 100)
// eval: (display-fill-column-indicator-mode 1)
// End:
///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
