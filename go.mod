///////////////////////////////////////////////////////////////////////////////////////////////////
// DPS8M Proxy - go.mod
// Copyright (c) 2025 Jeffrey H. Johnson
// Copyright (c) 2025 The DPS8M Development Team
// SPDX-License-Identifier: MIT
// scspell-id: 07ec62c0-6dbb-11f0-b70f-80ee73e9b8e7
///////////////////////////////////////////////////////////////////////////////////////////////////

// DPS8M Proxy
module gitlab.com/dps8m/proxy

///////////////////////////////////////////////////////////////////////////////////////////////////

go 1.25.0

///////////////////////////////////////////////////////////////////////////////////////////////////

require (
	github.com/arl/statsviz v0.7.1
	github.com/google/gops v0.3.29-0.20250514124927-a2d8f7790eac
	github.com/hashicorp/mdns v1.0.6
	github.com/klauspost/compress v1.18.0
	github.com/spf13/pflag v1.0.7
	github.com/ulikunitz/xz v0.5.15
	go.etcd.io/bbolt v1.4.3
	go.uber.org/goleak v1.3.1-0.20241121203838-4ff5fa6529ee
	golang.org/x/crypto v0.41.0
	golang.org/x/term v0.34.0
	kernel.org/pub/linux/libs/security/libcap/cap v1.2.76
)

///////////////////////////////////////////////////////////////////////////////////////////////////

require (
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/miekg/dns v1.1.68 // indirect
	golang.org/x/mod v0.27.0 // indirect
	golang.org/x/net v0.43.0 // indirect
	golang.org/x/sync v0.16.0 // indirect
	golang.org/x/sys v0.35.0 // indirect
	golang.org/x/tools v0.36.0 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.76 // indirect
)

///////////////////////////////////////////////////////////////////////////////////////////////////
// vim: set ft=gomod noexpandtab tabstop=4 cc=100 :
///////////////////////////////////////////////////////////////////////////////////////////////////
