//go:build windows

///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - trap_windows.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
// scspell-id: 210c336a-b24a-11f0-ab08-80ee73e9b8e7
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
//
//nolint:godoclint,nolintlint
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

var guiProcs = map[string]struct{}{
	"explorer.exe":                {},
	"powertoys.powerlauncher.exe": {},
	"searchapp.exe":               {},
	"searchhost.exe":              {},
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func getParentProc() (*windows.ProcessEntry32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return nil, fmt.Errorf("failed to create toolhelp32 snapshot: %w",
			err)
	}

	defer func() { _ = windows.CloseHandle(snap) }()

	procs := make(map[uint32]windows.ProcessEntry32)

	var procEnt windows.ProcessEntry32

	procEnt.Size = uint32(unsafe.Sizeof(procEnt))

	err = windows.Process32First(snap, &procEnt)
	for err == nil {
		procs[procEnt.ProcessID] = procEnt
		err = windows.Process32Next(snap, &procEnt)
	}

	if !errors.Is(err, windows.ERROR_NO_MORE_FILES) {
		return nil, fmt.Errorf("failed to get next process: %w",
			err)
	}

	pid := windows.GetCurrentProcessId()

	currentProc, ok := procs[pid]
	if !ok {
		return nil, errors.New("could not find current process")
	}

	parentProc, ok := procs[currentProc.ParentProcessID]
	if !ok {
		return nil, errors.New("could not find parent process")
	}

	return &parentProc, nil
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func guiLaunched() bool {
	pe, err := getParentProc()
	if err != nil {
		return false
	}

	parent := strings.ToLower(windows.UTF16ToString(pe.ExeFile[:]))

	_, ok := guiProcs[parent]

	return ok
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// Local Variables:
// mode: go
// tab-width: 4
// End:
///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
