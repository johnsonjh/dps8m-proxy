//go:build debug

///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - debug.go
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
package main

///////////////////////////////////////////////////////////////////////////////////////////////////

import (
	_ "expvar"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"time"

	"github.com/arl/statsviz"
)

///////////////////////////////////////////////////////////////////////////////////////////////////

const debugPort = 6060

///////////////////////////////////////////////////////////////////////////////////////////////////

func debugInit() {
	mux := http.NewServeMux()

	statsviz.Register(mux)

	mux.Handle("/debug/pprof/", http.DefaultServeMux)

	mux.Handle("/debug/vars", http.DefaultServeMux)

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `
        <html>
        <head><title>DPS8M Proxy Debugging Dashboard</title></head>
        <body>
            <h1>Debug Dashboard</h1>
            <ul>
                <li><a href="/debug/vars">expvar</a></li>
                <li><a href="/debug/pprof/">pprof</a></li>
                <li><a href="/debug/statsviz/">statsviz</a></li>
            </ul>
        </body>
        </html>
    `)
	})

	go func() {
		time.Sleep(10 * time.Millisecond)
		fmt.Printf("%s %sStarted debug HTTP server [:%d]\r\n",
			nowStamp(), bugPrefix(), debugPort)
		log.Print(http.ListenAndServe(fmt.Sprintf(":%d",
			debugPort),
			mux))
	}()
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func bugPrefix() string {
	if haveUTF8console {
		return "🐛 " // (De)bug
	}

	return ""
}

///////////////////////////////////////////////////////////////////////////////////////////////////

func printDebugURL(port int) {
	hostname, err := os.Hostname()
	if err != nil {
		log.Printf("%s %sCould not get hostname: %v",
			nowStamp(), warnPrefix(), err)

		return
	}

	addrs, err := net.LookupHost(hostname)
	if err != nil || len(addrs) == 0 {
		log.Printf("%s %sCould not resolve hostname: %v",
			nowStamp(), warnPrefix(), err)

		return
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=go noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
