//go:build !windows && !plan9 && !wasm
// +build !windows,!plan9,!wasm

///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - signals_unix.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
///////////////////////////////////////////////////////////////////////////////////////////////////

package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	"log"
	"os"
	"os/signal"
	"syscall"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

func setupSignalHandlers() {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan,
		syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT,
		syscall.SIGHUP, syscall.SIGUSR1,
		syscall.SIGUSR2)

	go func() {
		for s := range sigChan {
			switch s {
			case syscall.SIGHUP:
				log.Println("SIGHUP received: Reloading whitelist and/or blacklist.")
				reloadLists()

			case syscall.SIGUSR1:
				log.Println("SIGUSR1 received: Initiating graceful shutdown.")
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
				log.Println("SIGUSR2 received: Denying new connections.")
				denyNewConnectionsMode.Store(true)

			case syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT:
				immediateShutdown()
			}
		}
	}()
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
