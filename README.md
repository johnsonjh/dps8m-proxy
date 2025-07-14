<!-- Copyright (c) 2025 Jeffrey H. Johnson -->
<!-- Copyright (c) 2025 The DPS8M Development Team -->
<!-- SPDX-License-Identifier: MIT -->
<!-- vim: set ft=markdown expandtab cc=72 : -->
# dps8m-proxy

## Overview

The `proxy` (or `dps8m-proxy`) program acts as a multi-user
*terminal server* and proxy, accepting incoming **SSH** connections on
the front-end and relaying (*or proxying*) these connections to one or
more **TELNET** connections on the back-end.

Although this program was originally written to meet the needs of the
**BAN.AI Public Access Multics** system and the
[DPS8M Simulator](https://dps8m.gitlab.io) project, it may be useful
to anyone needing to provide modern SSH access to legacy systems.

## Features

<div>
&nbsp;&nbsp;✅ SSH ⟷ TELNET gateway<br>
&nbsp;&nbsp;✅ Session logging by date and host with automatic log compression<br>
&nbsp;&nbsp;✅ Banners for accepted (<code>motd.txt</code>) and denied (<code>deny.txt</code>) connections<br>
&nbsp;&nbsp;✅ Session connection monitoring with idle time tracking (and optional timeouts)<br>
&nbsp;&nbsp;✅ Interactive connection management
</div>

## Usage

### Installation

1. The software can be installed using `go install`:
   ```sh
   go install gitlab.com/dps8m/proxy@latest
   ```
   * This will download the needed source, compile, and install the
     binary to `${GOEXE}/bin/proxy` (which will be
     `${HOME}/go/bin/proxy` for most users).

2. You can also clone the
   [`git` repository](https://gitlab.com/dps8m/proxy.git)) and build
   the source code with:
   ```
   go build
   ```
   * A
   [`Makefile`](https://gitlab.com/dps8m/proxy/-/blob/master/Makefile)
   is also provided for convenience.
   * The `git` repository also contains
     example[`motd.txt`](https://gitlab.com/dps8m/proxy/-/blob/master/motd.txt)
     and
     [`deny.txt`](https://gitlab.com/dps8m/proxy/-/blob/master/deny.txt)
     files.

### Invocation

* The proxy can be invoked with the following command-line arguments:

```sh
Usage of proxy:
  -alt-host value
        Alternate TELNET targets (user@host:port) [allowed multiple times]
  -debug
        Debug TELNET negotiation
  -idle-max int
        Maximum connection idle time in seconds
  -log-dir string
        Base directory for session logs (default "./log")
  -no-banner
        Disable SSH connection banner
  -no-compress
        Disable gzip session log compression
  -no-log
        Disable all session logging
  -ssh-addr string
        SSH listen address (default ":2222")
  -telnet-host string
        Default TELNET target (host:port) (default "127.0.0.1:6180")
  -time-max int
        Maximum connection link time in seconds
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
  * `d` - Deny new Connections
  * `q` - Graceful shutdown
  * `Q` - Immediate shutdown (also via `^C`)

### Signals

* The proxy also acts on the following signals:
  * `SIGINT` - enables the *Immediate shutdown* mode
  * `SIGUSR1` - enables the *Graceful shutdown* mode
  * `SIGUSR2` - enables the *Deny new connections* mode
  * `SIGHUP` - detected but currently ignored

### Example setup

* 🚧 ***TODO*** — A complete example of a production installation
  using Linux, with the proxy on port 22, executing as an isolated and
  unprivileged user, in a `tmux` session — *should be provided soon*.

#### Example admin session

The following example shows the proxy listening on `*:2222` (the
default) for SSH connections (with any username), proxying them via
TELNET to port `6180` on the host `legacybox`.  Users who supply the
username `elsewhere` (*i.e.* `ssh -oPort=2222 elsewhere@proxybox`) are
proxied to port `9998` on the host `mainframe`.

```
$ dps8-proxy -telnet-host "legacybox:6180" -alt-host "elsewhere@mainframe:9998"  

c
Configuration
=============
* SSH LISTEN ON: :2222
* DEFAULT TARGET: legacybox:6180
* ALT TARGETS:
  * mainframe:9998 [elsewhere]
* TIME MAX: 0 seconds (disabled)
* IDLE MAX: 0 seconds (disabled)
* NO LOG: false
* LOG DIR: ./log
* NO LOG COMPRESS: false
* DEBUG: false
* GRACEFUL SHUTDOWN: false
* DENY NEW CONNECTIONS: false

2025/07/13 23:20:00 INITIATE [d4fcab] 23.45.67.89
2025/07/13 23:20:00 VALIDATE [d4fcab] elsewhere@23.45.67.89:22139
2025/07/13 23:20:00 ALTROUTE [d4fcab] elsewhere -> mainframe:9998

2025/07/13 23:20:03 INITIATE [08d679] 45.67.89.111
2025/07/13 23:20:03 VALIDATE [08d679] john@45.67.89.111:39969

l
Active Connections
==================
* ID d4fcab: elsewhere@23.45.67.89:22139 [Link: 5s, Idle: 5s]
* ID 08d679: john@45.67.89.111:39969 [Link: 2s, Idle: 2s]

k
Enter session ID to kill: 08d679
Killing connection 08d679...
2025/07/13 23:20:21 TEARDOWN [08d679] john@45.67.89.111
2025/07/13 23:20:21 DETACHED [08d679] john@45.67.89.111:39969 (link time 18s)
```

### User interaction

Users connected via SSH can send `^]` (*i.e.* `Control` + `]`) during
a session to access the following menu:

```
+====== MENU ======+
|                  |
|  B - Send Break  |
|  S - Show Stats  |
|  X - Disconnect  |
|                  |
+==================+
```

* `X` disconnects from the remote host (and ends the SSH session)
* `B` sends an IAC `BREAK` signal to the remote host
* `S` displays some session statistics:
  ```
  >> LNK - session total link time: 10s
  >> SSH - in: 354 bytes, out: 1289 bytes, in rate: 34.50 B/s, out rate: 125.63 B/s
  >> NVT - in: 1289 bytes, out: 353 bytes, in rate: 125.63 B/s, out rate: 34.41 B/s
  ```

## History

This version of the `dps8m-proxy` program is a from-scratch
[Golang](https://go.dev/) reimplementation of an older legacy program
of the same name, the original being an over-engineered and complex
multi-process application of more than 10,000 SLOC: ≅8,000 lines of
[C-Kermit](https://www.kermitproject.org/) (*yes, it has it’s own
[programming language](https://www.kermitproject.org/ckututor.html)*)
and ≅2,000 lines of [ksh93](https://github.com/ksh93/ksh) (along
with a small amount of Perl 5).

This new implementation replaces the original multi-process
architecture with lightweight *Goroutines*, and achieves improved
performance with greatly reduced system overhead.

At this time, approximately 75% of the original functionality has been
reimplemented in Go, with the current codebase coming in under 2,000
SLOC (as measured by [scc](https://github.com/boyter/scc)).  This is
an **85%** reduction in code compared size compared to the original
legacy codebase!

## Searching compressed logs

By default, session log files are automatically compressed when a
session is closed.  Oftentimes an administrator wishes to `grep`
through all of the logs, including those which have been compressed.

By default, session log files are compressed automatically when the
session terminates.  When reviewing the logs, administrators often
need to grep through all entries, including the compressed files.

We recommend using
[`ripgrep`](https://github.com/BurntSushi/ripgrep) (with the `-z`
option) or the [`zgrep`](https://www.gzip.org/) tool for this task.

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

This software is intended to be **secure**.  If you find any
security-related problems, please do not hesitate to open an Issue
or send an [e-mail](mailto:trnsz@pobox.com) to the author. The
canonical home of this software is
[https://gitlab.com/dps8m/proxy](https://gitlab.com/dps8m/proxy).

## License

The `dps8m-proxy` program is made available under the terms of the
[MIT License](https://opensource.org/license/mit), with some bundled
example and miscellaneous files distributed under the terms of the
[MIT No Attribution License](https://opensource.org/license/mit-0).
