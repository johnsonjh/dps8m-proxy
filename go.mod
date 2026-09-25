///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - go.mod
// Copyright (c) 2025-2026 Jeffrey H. Johnson
// Copyright (c) 2025-2026 The DPS8M Development Team
// SPDX-License-Identifier: MIT
// scspell-id: 07ec62c0-6dbb-11f0-b70f-80ee73e9b8e7
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
module gitlab.com/dps8m/proxy

///////////////////////////////////////////////////////////////////////////////////////////////////

go 1.27.1

///////////////////////////////////////////////////////////////////////////////////////////////////

// Direct dependencies
require (
	github.com/arl/statsviz v0.8.2
	github.com/google/gops v0.3.29
	github.com/hashicorp/mdns v1.0.7
	github.com/klauspost/compress v1.20.1
	github.com/sorairolake/lzip-go v0.3.8
	github.com/spf13/pflag v1.0.11-0.20260921074312-c966cfef4737
	github.com/ulikunitz/xz v0.5.17
	go.etcd.io/bbolt v1.5.0
	go.uber.org/goleak v1.3.1-0.20260915222441-b656bfda2fbf
	golang.org/x/crypto v0.57.0
	golang.org/x/sys v0.48.0
	golang.org/x/term v0.46.0
	golang.org/x/text v0.42.0
	kernel.org/pub/linux/libs/security/libcap/cap v1.2.78
)

// Indirect dependencies
require (
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	golang.org/x/net v0.59.0 // indirect
	golang.org/x/tools v0.50.0 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.78 // indirect
)

///////////////////////////////////////////////////////////////////////////////////////////////////

///////////////////////////////////////////////////////////////////////////////////////////////////
// Local Variables:
// mode: go
// tab-width: 4
// fill-column: 100
// eval: (setq-local display-fill-column-indicator-column 100)
// eval: (display-fill-column-indicator-mode 1)
// End:
///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=gomod noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
