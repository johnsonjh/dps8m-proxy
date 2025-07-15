<!-- Copyright (c) 2025 Jeffrey H. Johnson -->
<!-- Copyright (c) 2025 The DPS8M Development Team -->
<!-- SPDX-License-Identifier: MIT -->
<!-- vim: set ft=markdown expandtab cc=72 : -->
# dps8m-proxy

## Overview

The **`proxy`** (or **`dps8m-proxy`**) program acts as a multi-user
*terminal server* and proxy, accepting incoming **SSH** connections on
the front-end and relaying (*or proxying*) these connections to one or
more **TELNET** connections on the back-end.

Although this project was originally developed to meet the needs of
the **BAN.AI Public Access Multics** system and the
[DPS8M Simulator](https://dps8m.gitlab.io) projects, it may be useful
to anyone who wants to provide modern SSH access to legacy systems.

## Features

* ✅ **SSH**⟷**TELNET** gateway
* ✅ Full IPv6 support
* ✅ Access control whitelist/blacklist (by IP address or CIDR block)
* ✅ Session monitoring and logging (by date/time and host)
* ✅ Automatic logfile compression (gzip, xz, zstandard)
* ✅ Banners for accepted, denied, and blocked connections
* ✅ Session connection monitoring with idle time tracking (and optional timeouts)
* ✅ Interactive connection management for administrators
* ✅ User access to **TELNET** features (*e.g.* line BREAK, AYT) and statistics
* ✅ Link filtering
* ✅ Transparent key remapping mode (translating movement keys to Emacs sequences)
* ✅ Live streaming connection sharing (read-only)
  * 🤝 Allows users to share their session with one or more viewers

## Usage

### Installation

* The software can be installed using `go install`:
  ```sh
  go install gitlab.com/dps8m/proxy@latest
  ```
  * This will download the needed source, compile, and install the
    binary to `${GOEXE}/bin/proxy` (which will be
    `${HOME}/go/bin/proxy` for most users).

* You can also clone the
  [`git` repository](https://gitlab.com/dps8m/proxy.git) and build
  the source code with:
  ```
  go build
  ```
  * A
  [`Makefile`](https://gitlab.com/dps8m/proxy/-/blob/master/Makefile)
  is also provided for convenience.
  * The `git` repository also contains several example files.

### Invocation

* The proxy can be invoked with the following command-line arguments:

```
Usage of proxy:
  -allow-root
        Allow running as root (UID 0) [strongly discouraged!]
  -alt-host value
        Alternate TELNET targets (username@host:port) [allowed multiple times]
  -blacklist string
        Blacklist file (optional)
  -compress-algo string
        Compression algorithm [gzip, xz, zstd] (default "gzip")
  -console-log string
        Enable console logging [requires 'quiet' or 'noquiet' argument]
  -debug
        Debug TELNET negotiation
  -idle-max int
        Maximum connection idle time in seconds
  -log-dir string
        Base directory for logs (default "./log")
  -log-perm value
        Permissions for log files (umask, e.g., 0600, 0644) (default 600)
  -no-banner
        Disable SSH connection banner
  -no-compress
        Disable session and console log compression
  -no-log
        Disable all session logging
  -ssh-addr value
        SSH listener address [allowed multiple times]
  -telnet-host string
        Default TELNET target (host:port) (default "127.0.0.1:6180")
  -time-max int
        Maximum connection link time in seconds
  -version
        Show version information
  -whitelist string
        Whitelist file (optional)
```

### Port binding

* If you want to listen on the regular SSH port of 22 (without
  running as `root`, which is strongly discouraged) on Linux systems
  you can use `setcap` to allow the proxy to bind to low ports:
  ```sh
  sudo setcap 'cap_net_bind_service=+ep' "/path/to/proxy"
  ```

### Admin interaction

* The running proxy can be controlled with the following commands:
  * `?` - Show help text
  * `c` - Show proxy configuration
  * `l` - List active connections
  * `k` - Kill connection
  * `d` - Deny new connections
  * `r` - Reload access control lists
  * `q` - Graceful shutdown
  * `Q` - Immediate shutdown (also via `^C`)

### Signals

* The proxy also acts on the following signals:
  * `SIGINT` - enables the *Immediate shutdown* mode
  * `SIGUSR1` - enables the *Graceful shutdown* mode
  * `SIGUSR2` - enables the *Deny new connections* mode
  * `SIGHUP` - reloads *access control lists* (`-whitelist`, `-blacklist`)

### Example setup

* 🚧 A complete example of a production installation for Linux, with
  the proxy on port 22, running as an unprivileged user, and managed
  with a `tmux` session *is coming soon*.

#### Example admin session

The following example shows the proxy listening on `*:2222` (the
default) for SSH connections (with any username), proxying them via
TELNET to port `6180` on the host `legacybox`.  Users who supply the
username `elsewhere` (*e.g.* `ssh -oPort=2222 elsewhere@proxybox`) are
proxied to port `9998` on the host `mainframe`.

```
$ dps8-proxy -telnet-host "legacybox:6180" -alt-host "elsewhere@mainframe:9998"  

> c
2025/07/15 23:20:00 DPS8M Proxy (2025-Jul-15) [linux/amd64]

DPS8M PROXY Configuration
=========================
* SSH LISTEN ON: :2222, :2223, localhost:8000
* DEFAULT TARGET: 127.0.0.1:6180
* ALT TARGETS:
  * 127.0.2.1:9998 [opcon]
  * 127.0.0.1:9999 [banai]
* TIME MAX: 0 seconds
* IDLE MAX: 0 seconds
* LOG DIR: ./log
* NO SESSION LOG: false
* CONSOLE LOG: log/2025/07/15/console.log
* NO LOG COMPRESS: false
* COMPRESS ALGO: gzip
* LOG PERMISSIONS: 0600
* GRACEFUL SHUTDOWN: false
* DENY NEW CONNECTIONS: false
* BLACKLIST: disabled
* WHITELIST: disabled
* DEBUG: false
* RESOURCE USAGE:
  * MEMORY USAGE: 696.7 KiB
  * GOROUTINES: 9 active
  * CPU TIME USED: 0s
* CONNECTIONS (CUM.): 0 SSH, 0 TELNET


2025/07/15 23:20:00 INITIATE [d4fcab] 23.45.67.89
2025/07/15 23:20:00 VALIDATE [d4fcab] elsewhere@23.45.67.89:22139
2025/07/15 23:20:00 ALTROUTE [d4fcab] elsewhere -> mainframe:9998

2025/07/15 23:20:03 INITIATE [08d679] 45.67.89.111
2025/07/15 23:20:03 VALIDATE [08d679] john@45.67.89.111:39969

> l
Active Connections
==================
* ID d4fcab: elsewhere@23.45.67.89:22139 [Link: 5s, Idle: 5s]
* ID 08d679: john@45.67.89.111:39969 [Link: 2s, Idle: 2s]

> k
Enter session ID to kill: 08d679
Killing connection 08d679...
2025/07/15 23:20:21 TEARDOWN [08d679] john@45.67.89.111
2025/07/15 23:20:21 DETACHED [08d679] john@45.67.89.111:39969 (link time 18s)
```

### User interaction

Users connected via SSH can send `^]` (*i.e.* `Control + ]`) during
a session to access the following menu:

```
+======= MENU ========+
|                     |
|  A - Send AYT       |
|  B - Send Break     |
|  K - Toggle Keymap  |
|  N - Send NOP       |
|  S - Show Status    |
|  X - Disconnect     |
|                     |
+=====================+
```

* `A` sends an IAC `AYT` (*Are You There?*) to the remote host
* `B` sends an IAC `BREAK` signal to the remote host
* `K` toggles the transparent key remapping mode, which translates
  modern `xterm`/`VT320` movement key inputs to Emacs sequences:
  * `Control-Arrow_Up` ⟶ `Escape [`
  * `C-Arrrow_Down` ⟶ `Escape, ]`
  * `C-Arrow_Right` ⟶ `Escape, f`
  * `C-Arrow_Left` ⟶ `Escape, b`
  * `Home` ⟶ `Control-A`
  * `Delete` ⟶ `Control-D`
  * `End` ⟶ `Control-E`
  * `Page_Up` ⟶ `Escape, v`
  * `Page_Down` ⟶ `Control-V`
  * `Arrow_Up` ⟶ `Control-P`
  * `Arrow_Down` ⟶ `Control-N`
  * `Arrow_Right` ⟶ `Control-F`
  * `Arrow_Left` ⟶ `Control-B`
* `N` sends an IAC `NOP` (*No Operation*) to the remote host
* `S` displays the status the session and some statistics:
  ```
  >> LNK - The username '_gRSyWHxPcMp2MWvtmWWF' can be used to share this session.
  >> SSH - in:   58 B,   out: 4.82 KiB, in rate:   4 B/s, out rate: 381 B/s
  >> NVT - in: 4.82 KiB, out:   57 B,   in rate: 381 B/s, out rate:   4 B/s
  >> LNK - link time: 13s (Emacs keymap enabled)
  ```
* `X` disconnects from the remote host (and ends the SSH session)

### Connection sharing

* The user can share the username presented above with others,
  allowing the session to be viewed live (read-only) by one or more
  viewers:
  ```sh
  $ ssh _gRSyWHxPcMp2MWvtmWWF@proxybox

  CONNECTION from remote.com [18.17.16.15] started at 2025/07/15 08:22:55.
  This is a READ-ONLY shared monitoring session.
  Send Control-] to disconnect.
  ```

## History

This version of the `proxy` program is a from-scratch
[Golang](https://go.dev/) re-implementation of an older legacy program
of the same name, the original being an over-engineered and complex
multi-process application of more than 10,000 SLOC: ≅8,000 lines of
[C-Kermit](https://www.kermitproject.org/) (*yes, it has it’s own
[programming language](https://www.kermitproject.org/ckututor.html)*)
and ≅2,000 lines of [ksh93](https://github.com/ksh93/ksh) (along
with a small amount of Perl 5), excluding some optional components.

This new implementation replaces the original multi-process
architecture with lightweight *Goroutines*, and achieves improved
performance with greatly reduced system overhead.

At this time, approximately 70% of the original functionality has been
re-implemented in Go, with the current codebase coming in under 2,000
SLOC (as measured by [scc](https://github.com/boyter/scc)).

This is an **85%** reduction in code compared size compared to the
original legacy codebase.

## Future plans

Some features are still missing in this implementation and will be
added in future updates:

* The original legacy software has features not yet re-implemented
  CAPTCHAs, throttling, and **TELNET** flow control support.
* The **TELNET** features currently implemented are minimal—enough
  for supporting **DPS8M**.  Improved protocol support is planned.

## Not planned

The original legacy software “grew” many features that would be
difficult to re-implement but also had very little actual usage.
The following are some of these features, which *may* be added at a
later date, but are considered to be ***very low priority***:

* **TELNET**, **SUPDUP**, and **TN3370** listener/target support
* **DECnet**/**CTERM** listener/target support
* Ability for users to download
  [ttyrec](https://nethackwiki.com/wiki/Ttyrec) format session logs

## Searching compressed logs

By default, session logfiles are compressed automatically when the
session terminates, and console log files are compressed when the
log rolls over to a new day.  When reviewing logs, administrators
often need to grep through all the past data, including the
compressed files. We recommend using
[`ripgrep`](https://github.com/BurntSushi/ripgrep) (with the `-z`
option) for this task.

## Using OpenSSH host keys

If you have existing [OpenSSH](https://www.openssh.com/) Ed25519 or
RSA host keys that you want to use with the proxy, you’ll need to
convert those keys to standard PEM format. **NB**: These instructions
*do not* include specific instructions for safe handling of key file
permissions—we assume you know what you’re doing!

1. Make a *copy* the key files you wish to convert.  Be aware that
   these copies will be *overwritten* in the conversion process:

   ```sh
   cp /etc/ssh/ssh_host_rsa_key ssh_host_rsa_key.tmp
   cp /etc/ssh/ssh_host_ed25519_key ssh_host_ed25519_key.tmp
   ```

2. Convert the key (using `ssh-keygen`) and rename it appropriately:
   ```sh
   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_rsa_key.tmp
   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_ed25519_key.tmp
   mv ssh_host_rsa_key.tmp ssh_host_rsa_key.pem
   mv ssh_host_ed25519_key.tmp ssh_host_ed25519_key.pem 
   ```
## Security

* The canonical home of this software is
[https://gitlab.com/dps8m/proxy](https://gitlab.com/dps8m/proxy).
* This software is intended to be **secure**.  If you find any
security-related problems, please do not hesitate to open an Issue
or send an [e-mail](mailto:trnsz@pobox.com) to the author.

## License

* The `proxy` program is made available under the terms of the
[MIT License](https://opensource.org/license/mit), with some bundled
example and miscellaneous files distributed under the terms of the
[MIT No Attribution License](https://opensource.org/license/mit-0).
