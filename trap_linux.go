//go:build linux

///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - trap_linux.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
// scspell-id: 7002af98-b651-11f0-9b9e-80ee73e9b8e7
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
//
//nolint:godoclint,nolintlint
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

var guiLaunchers = map[string]struct{}{
	"budgie-desktop": {},
	"caja":           {},
	"cinnamon":       {},
	"dde-desktop":    {},
	"dolphin":        {},
	"doublecmd":      {},
	"dtfile":         {},
	"far2l":          {},
	"file-roller":    {},
	"gnome-shell":    {},
	"lf":             {},
	"mate-panel":     {},
	"mc":             {},
	"nautilus":       {},
	"nemo":           {},
	"nnn":            {},
	"pcmanfm":        {},
	"pcmanfm-qt":     {},
	"plasmashell":    {},
	"ranger":         {},
	"spf":            {},
	"thunar":         {},
	"unixtree":       {},
	"vifm":           {},
	"xfdesktop":      {},
	"xplr":           {},
	"yazi":           {},
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func openProcDir(pid int) (*os.File, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid pid: %d",
			pid)
	}

	procDir, err := os.OpenFile(fmt.Sprintf("/proc/%d",
		pid), unix.O_PATH|unix.O_DIRECTORY, 0)
	if err != nil {
		return nil, fmt.Errorf("could not open /proc/%d directory: %w",
			pid, err)
	}

	return procDir, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func getProcName(pid int) (string, error) {
	procDir, err := openProcDir(pid)
	if err != nil {
		return "", err
	}

	defer func() { _ = procDir.Close() }()

	commFd, err := unix.Openat(int(procDir.Fd()),
		"comm", unix.O_RDONLY, 0)
	if err != nil {
		return "", fmt.Errorf("could not openat 'comm' for pid %d: %w",
			pid, err)
	}

	commFile := os.NewFile(uintptr(commFd),
		fmt.Sprintf("/proc/%d/comm",
			pid))

	if commFile == nil {
		_ = unix.Close(commFd)

		return "", fmt.Errorf("failed to create os.File from descriptor for pid %d",
			pid)
	}

	defer func() { _ = commFile.Close() }()

	const maxCommLen = 32 // TASK_COMM_LEN * 2

	lr := io.LimitReader(commFile, maxCommLen+1)

	content, err := io.ReadAll(lr)
	if err != nil {
		return "", fmt.Errorf("could not read 'comm' for pid %d: %w",
			pid, err)
	}

	if len(content) > maxCommLen {
		return "", fmt.Errorf("'comm' for pid %d is unexpectedly large (> %d bytes)",
			pid, maxCommLen)
	}

	return strings.TrimSpace(string(content)), nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func getPpid(pid int) (int, error) {
	procDir, err := openProcDir(pid)
	if err != nil {
		return 0, err
	}

	defer func() { _ = procDir.Close() }()

	statusFd, err := unix.Openat(int(procDir.Fd()),
		"status", unix.O_RDONLY, 0)
	if err != nil {
		return 0, fmt.Errorf("could not openat 'status' for pid %d: %w",
			pid, err)
	}

	statusFile := os.NewFile(uintptr(statusFd),
		fmt.Sprintf("/proc/%d/status",
			pid))

	if statusFile == nil {
		_ = unix.Close(statusFd)

		return 0, fmt.Errorf("failed to create os.File from descriptor for pid %d",
			pid)
	}

	defer func() { _ = statusFile.Close() }()

	scanner := bufio.NewScanner(statusFile)

	for scanner.Scan() {
		line := scanner.Text()

		if strings.HasPrefix(line, "PPid:") {
			fields := strings.Fields(line)

			if len(fields) < 2 {
				return 0, fmt.Errorf("malformed PPid line in status for pid %d",
					pid)
			}

			ppid, err := strconv.Atoi(fields[1])
			if err != nil {
				return 0, fmt.Errorf("could not parse PPid for pid %d: %w",
					pid, err)
			}

			return ppid, nil
		}
	}

	err = scanner.Err()
	if err != nil {
		return 0, fmt.Errorf("error reading status file for pid %d: %w",
			pid, err)
	}

	return 0, fmt.Errorf("could not find PPid in status for pid %d",
		pid)
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func isLauncher(pid int) bool {
	procName, err := getProcName(pid)
	if err != nil {
		return false
	}

	_, isLauncher := guiLaunchers[strings.ToLower(procName)]

	return isLauncher
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func guiLaunched() bool {
	ppid := os.Getppid()

	if isLauncher(ppid) {
		return true
	}

	gppid, err := getPpid(ppid)
	if err != nil {
		return false
	}

	return isLauncher(gppid)
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
