//go:build !windows && !plan9 && !wasm

///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - signals_common.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
// scspell-id: 281f4d40-6bd2-11f0-aaf0-80ee73e9b8e7
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
//
//nolint:godoclint,nolintlint
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"log"
	"os"
	"syscall"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

func handleSignal(s os.Signal) {
	switch s {
	case syscall.SIGHUP:
		log.Printf("%sSIGHUP received: Reloading whitelist and/or blacklist.\r\n",
			bellPrefix())
		reloadLists()

	case syscall.SIGUSR1:
		log.Printf("%sSIGUSR1 received: Initiating graceful shutdown.\r\n",
			bellPrefix())
		gracefulShutdownMode.Store(true)
		connectionsMutex.Lock()

		if len(connections) == 0 {
			connectionsMutex.Unlock()

			select {
			case shutdownSignal <- struct{}{}:

			default:
			}
		} else {
			connectionsMutex.Unlock()
		}

	case syscall.SIGUSR2:
		log.Printf("%sSIGUSR2 received: Denying new connections.\r\n",
			bellPrefix())
		denyNewConnectionsMode.Store(true)

	case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
		immediateShutdown()
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
