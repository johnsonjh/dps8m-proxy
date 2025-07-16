//go:build linux || android

///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - capability_linux.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"log"
	"os"
	"path/filepath"

	"kernel.org/pub/linux/libs/security/libcap/cap"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

func resolveExePath() string {
	var exe string
	var err error

	exe, err = os.Executable()

	if err != nil { // Fallback to /proc
		if realPath, err2 := os.Readlink("/proc/self/exe"); err2 == nil {
			exe = realPath
			err = nil
		}
	}

	if err != nil || exe == "" { // Fallback to argv[0]
		if len(os.Args) > 0 && os.Args[0] != "" {
			exe = os.Args[0]
		} else { // Fallback to "proxy"
			exe = "proxy"
		}
	}

	if realPath, err := filepath.EvalSymlinks(exe); err == nil {
		exe = realPath
	}

	if abs, err := filepath.Abs(exe); err == nil {
		exe = abs
	}

	return exe
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func checkCapability() {
	hasBindCap := false
	if cv, err := cap.FromName("cap_net_bind_service"); err == nil {
		hasBindCap, _ = cap.GetProc().GetFlag(cap.Effective, cv)
	}

	exePath := resolveExePath()
	if !hasBindCap && os.Getuid() != 0 {
		log.Println("CAP_NET_BIND_SERVICE is required to bind privileged (<1024) ports")
		log.Printf("Fix: sudo setcap 'cap_net_bind_service+ep' %q\n", exePath)
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
