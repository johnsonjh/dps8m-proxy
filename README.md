<!-- Copyright (c) 2025 Jeffrey H. Johnson -->
<!-- Copyright (c) 2025 The DPS8M Development Team -->
<!-- SPDX-License-Identifier: MIT -->
<!-- vim: set ft=markdown expandtab cc=72 : -->
<!-- NB: Do not modify README.md directly; modify README.md.tmpl -->
# proxy

[![Go Report Card](https://goreportcard.com/badge/gitlab.com/dps8m/proxy)](https://goreportcard.com/report/gitlab.com/dps8m/proxy)
[![REUSE status](https://api.reuse.software/badge/gitlab.com/dps8m/proxy)](https://api.reuse.software/info/gitlab.com/dps8m/proxy)

## Overview

The **`proxy`** program acts as a multi-user *terminal server* and
relay, accepting incoming SSH client connections on the front-end
(*listeners*) and proxying these connections to one or more TELNET
servers on the back-end (*targets*).

This project was originally developed to meet the needs of the
*BAN.AI Public Access Multics* system and the
[DPS8M Simulator](https://dps8m.gitlab.io) project, but may be useful
to anyone who wants to offer SSH access to legacy systems.

## Features

* ✅ SSH ⟷ TELNET gateway
* ✅ Full IPv6 support
* ✅ Access control whitelist/blacklist (by IP address or CIDR block)
* ✅ Independent console and session logging (by date/time and host)
* ✅ Automatic log-file compression (using gzip, xz, or zstandard)
* ✅ Banners for accepted, denied, and blocked connections (configurable per target)
* ✅ Session connection monitoring and idle time tracking (with optional timeouts)
* ✅ Interactive connection management for administrators
* ✅ Optional support for process management using `systemd` on Linux
* ✅ User access to TELNET features (*e.g.*, line BREAK, AYT) and statistics
* ✅ Link filtering
* ✅ Transparent key remapping mode (translating movement keys to Emacs sequences)
* ✅ Live streaming connection sharing (read-only)
  * 🤝 Allows users to share their session with one or more viewers

## Usage

### Installation

A recent version of [Go](https://go.dev/) is required to build `proxy`
from source code.

* You can clone the
  [`git` repository](https://gitlab.com/dps8m/proxy.git) and build
  the source code using `make`:

  ```sh
  git clone https://gitlab.com/dps8m/proxy.git
  cd proxy
  make
  ```

  * If you don’t have a (POSIX/GNU/BSD) `make` available for some
    reason, then building with `go build` is sufficient.

  * A [`.cross.sh`](.cross.sh) cross-compilation helper script is
    provided (which can be called with `make cross`) that attempts to
    build `proxy` binaries for *all* supported `GOOS` and `GOARCH`
    combinations.  At the time of writing, 41 binaries are built for
    12 operating systems (IBM AIX, Android, Apple macOS, Dragonfly BSD,
    FreeBSD, illumos, Linux, NetBSD, OpenBSD, Plan 9, Solaris, and
    Microsoft Windows) running on 13 different hardware architectures.

* You can also install this software using `go install`:

  ```sh
  go install gitlab.com/dps8m/proxy@latest
  ```

  * Installations using `go install` download the required sources,
    compile, and install the binary to `${GOEXE}/bin/proxy` (which will
    be `${HOME}/go/bin/proxy` for most users).

### Invocation

* The `proxy` command can be invoked with the following command-line
  arguments:

```
Usage of ./proxy:
  -0, --allow-root              Allow running as root (UID 0)
  -l, --ssh-addr strings        SSH listener address(es)
                                   [e.g., ":2222", "[::1]:8000"]
                                   (multiple allowed) (default ":2222")
  -n, --no-banner               Disable SSH connection banner
  -t, --telnet-host string      Default TELNET target [host:port]
                                   (default "127.0.0.1:6180")
  -a, --alt-host string         Alternate TELNET target(s) [sshuser@host:port]
                                   (multiple allowed)
  -d, --debug                   Debug TELNET option negotiation
  -L, --log-dir string          Base directory for logs (default "./log")
  -o, --no-log                  Disable all session logging
                                   (for console logging, see "--console-log")
  -c, --console-log string      Enable console logging ["quiet", "noquiet"]
  -C, --compress-algo string    Compression algorithm ["gzip", "xz", "zstd"]
                                   (default "gzip")
  -s, --compress-level string   Compression level for gzip and zstd algorithms
                                   ["fast", "normal", "high"]
                                   (default "normal")
  -x, --no-compress             Disable session and console log compression
  -p, --log-perm octal          Permissions (octal) for new log files
                                   [ e.g., "600", "644"] (default "600")
  -P, --log-dir-perm octal      Permissions (octal) for new log directories
                                   [e.g., "755", "750"] (default "750")
  -i, --idle-max int            Maximum connection idle time allowed [seconds]
  -m, --time-max int            Maximum connection link time allowed [seconds]
  -b, --blacklist string        Enable blacklist [filename] (no default)
  -w, --whitelist string        Enable whitelist [filename] (no default)
  -v, --version                 Show version information
pflag: help requested
```

Most of these command-line arguments are straightforward and their
usage should be obvious, and those that require demystification are,
hopefully, documented here:

* Logging of sessions is *enabled* by default.  Logging of console
  messages is *disabled* by default.

  * Console logging, if enabled, supports two modes: `quiet` and
    `noquiet`.  In `quiet` mode, all non-fatal messages are logged
    **only** to the log file, where in `noquiet` mode, messages are
    logged to **both** the console and the log file.

* All incoming SSH users are connected to the default TELNET target,
  unless their supplied SSH username matches an alternate target
  enabled with the `--alt-host` flag.  The alt-host syntax is
  `sshuser@host:port`, where `sshuser` is the SSH username, and the
  `host:port` is the TELNET target.

* All users connecting with SSH are shown a banner which includes
  details such as the date and time of the session, their IP address,
  and possibly a resolved host name.  This can be disabled with
  `--no-banner`.

* The `--no-banner` command disables only those lines described above.
  It does *not* disable the file-based banner content.  These are the
  three primary text files which can be displayed to connecting
  SSH users:

  | File        | Purpose                                                                   |
  |------------:|:--------------------------------------------------------------------------|
  | `block.txt` | Displayed before disconnecting connections matching the blacklist         |
  | `deny.txt`  | Displayed when denying target sessions (*e.g.*, during graceful shutdown) |
  | `issue.txt` | Displayed to users before their actual session with the target begins     |

  * When multiple are targets defined using the `--alt-host`
    functionality, the system will display a file that matches `-NAME`
    before the `.txt` extension.  For example, if you have defined a
    target as  `oldunix@10.0.5.9:3333` the proxy will look for
    `block-oldunix.txt`, `deny-oldunix.txt`, and `issue-oldunix.txt`
    files to serve to the connected user, before beginning their
    session with the target (via TELNET to `10.0.5.9:3333`).  If any
    of the target-specific text files do not exist, then the standard
    files will be served.
  * To disable the file-based banner for specific targets only, you
    can create empty files using the naming scheme described above.
    You can also remove *all* of these files if you don’t want to
    use this functionality.

* You need to start `proxy` using the `--whitelist` and/or
  `--blacklist` argument to enable the access control functionality.
  If *only* the whitelist is enabled, then all connections will be
  denied by default.  Note that if *only* the whitelist is enabled, it
  will be impossible to exempt individual IP addresses within a range
  that has been blocked.  It is recommended that you *both* lists
  when using the access control feature.

  * The format of the whitelist and blacklist is an IPv4 or IPv6
    address (*e.g.*, `23.215.0.138`, `2600:1406:bc00:53::b81e:94ce`),
    or a CIDR block (*e.g.*, `123.45.0.0/17` which covers `123.45.0.0`
    to `123.45.127.255`, or `2600:1408:ec00:36::/64` covering
    `2600:1408:ec00:36:0000:0000:0000:0000` to
    `2600:1408:ec00:36:ffff:ffff:ffff:ffff`).

  * The whitelist always takes precedence over the blacklist.
    If an address is allowed due to a whitelist match that would
    have otherwise been blocked by the blacklist, it is tagged as
    `EXEMPTED` in the logs.

* The `-v` or `--version` command shows detailed version information,
  including the versions of any embedded dependencies as well as the
  version of the Go compiler used to build the software:

```
DPS8M Proxy v0.0.0 (2025-Jul-18 gce1a973) [linux/amd64]

+===========================+=========+
| Component                 | Version |
+===========================+=========+
| dps8m/proxy               | v0.0.0  |
| klauspost/compress        | v1.18.0 |
| spf13/pflag               | v1.0.7  |
| ulikunitz/xz              | v0.5.12 |
| golang.org/x/crypto       | v0.40.0 |
| kernel.org/.../libcap/cap | v1.2.76 |
| kernel.org/.../libcap/psx | v1.2.76 |
| Go compiler (gc)          | v1.24.5 |
+===========================+=========+
```

* If you need to see additional details about the `proxy` binary,
  you can run `go version -m proxy`.

### Port binding

* If you want to listen on the regular SSH port of 22 (without
  running as `root`, which is strongly discouraged), on Linux systems
  you can use `setcap` to allow the proxy to bind to low ports:

  ```sh
  sudo setcap 'cap_net_bind_service=+ep' "/path/to/proxy"
  ```

* If this is necessary (*i.e.*, a non-root user on Linux is attempting
  to bind an SSH listener to a privileged port and the
  `CAP_NET_BIND_SERVICE` capability is not currently effective), the
  software should provide a warning message with the above
  instructions.

### Admin interaction

* The running proxy can be controlled interactively with the following
  admin console commands:
  * `?` — Show help text
  * `c` — Show proxy configuration
  * `v` — Show version details
  * `l` — List active connections
  * `k` — Kill a connection
  * `d` — Deny new connections
  * `r` — Reload access control lists
  * `q` — Graceful shutdown
  * `Q` — Immediate shutdown (also via `^C`)
[]()

[]()
Most of these admin console commands are straightforward and should
be self-explanatory, although there are a few options that merit
further clarification:

* When the **Graceful shutdown** mode is active, all new connections
  are denied (and are served an appropriate `deny.txt` banner).  Once
  all clients have disconnected, the proxy software will exit.  Note
  that new *monitoring sessions* can still connect to observe active
  users, as these sessions are automatically closed when their
  observation target disconnects.

* When the **Deny new connections** mode is active, all new connections
  are denied (and are served an appropriate `deny.txt` banner).  In
  addition, any *logging* of new connection attempts, including any
  denied and/or rejected connections, is suppressed.  This can be
  useful if the admin console is overwhelmed with logging activity
  (such as during bot attacks, busy periods, or when troubleshooting).
  Activating this mode can help reduce console noise, making it easier
  to perform admin actions such as viewing the configuration, or
  listing and killing active connections.

### Signals

* The proxy also acts on the following signals (on systems where
  signals are supported):

  |    Signal | Action                                                          |
  |----------:|:----------------------------------------------------------------|
  | `SIGINT`  | Enables the **Immediate shutdown** mode                         |
  | `SIGQUIT` | Enables the **Immediate shutdown** mode                         |
  | `SIGUSR1` | Enables the **Graceful shutdown** mode                          |
  | `SIGUSR2` | Enables the **Deny new connections** mode                       |
  | `SIGHUP`  | Reloads *access control lists* (`--whitelist`, `--blacklist`)   |

### Automation with systemd

If you are running on the proxy on a Linux system, you can use
`systemd` to manage the service, while still preserving your
access to the interactive admin console.

* See the [`dps8m-proxy.service`](systemd/dps8m-proxy.service) file
  for details.

### User interaction

Users connected via SSH can send `^]` (*i.e.*, `Control + ]`) during
their session to access the following following TELNET control
features:

* `A` — sends an IAC `AYT` (*Are You There?*) to the remote host

* `B` — sends an IAC `BREAK` signal to the remote host

* `K` — toggles the transparent key remapping mode, which translates
  modern `xterm`/`VT320` movement key inputs to Emacs sequences:

  |             Input | Output        |
  |------------------:|:--------------|
  | `Control + Up`    | `Escape, [`   |
  | `Control + Down`  | `Escape, ]`   |
  | `Control + Right` | `Escape, f`   |
  | `Control + Left`  | `Escape, b`   |
  | `Home`            | `Control + A` |
  | `Delete`          | `Control + D` |
  | `End`             | `Control + E` |
  | `Up`              | `Escape + v`  |
  | `Down`            | `Control + V` |
  | `Up`              | `Control + P` |
  | `Down`            | `Control + N` |
  | `Right`           | `Control + F` |
  | `Left`            | `Control + B` |

* `N` — sends an IAC `NOP` (*No Operation*) to the remote host

* `S` — displays the status the session, sharing information, and some
  statistics:

  ```
  >> LNK - The username '_gRSyWHxPcMp2MWvtmWWF' can be used to share this session.
  >> SSH - in:   58 B,   out: 4.82 KiB, in rate:   4 B/s, out rate: 381 B/s
  >> NVT - in: 4.82 KiB, out:   57 B,   in rate: 381 B/s, out rate:   4 B/s
  >> LNK - link time: 13s (Emacs keymap enabled)
  ```

* `X` — disconnects from the remote host (and ends the SSH session)

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

This is a from-scratch re-implementation (in
[Go](https://go.dev/)) of an older legacy program of the same name.

The original software used a multi-process architecture and consisted
of nearly **15,000 lines** of haphazardly constructed code: ≅14,000
lines of mostly [C-Kermit](https://www.kermitproject.org/) (*yes, the
[programming language](https://www.kermitproject.org/ckscripts.html)*)
and [`ksh93`](https://github.com/ksh93/ksh) (along with some C, Python,
and Perl) which was difficult to maintain, configure, and securely
install.

This new implementation uses many lightweight *Goroutines* instead of
spawning multiple processes, resulting in significantly improved
performance and reduced system overhead.

### Stats

The new `proxy` program is considerably simpler than its legacy
predecessor (code statistics provided by
[`scc`](https://github.com/boyter/scc)):

<table id="scc-table">
	<thead><tr>
		<th>Language</th>
		<th>Files</th>
		<th>Lines</th>
		<th>Blank</th>
		<th>Comment</th>
		<th>Code</th>
		<th>Complexity</th>
		<th>Bytes</th>
		<th>Uloc</th>
	</tr></thead>
	<tbody><tr>
		<th>Go</th>
		<th>7</th>
		<th>3117</th>
		<th>538</th>
		<th>151</th>
		<th>2428</th>
		<th>781</th>
		<th>85082</th>
		<th>1569</th>
	</tr><tr>
		<th>Makefile</th>
		<th>1</th>
		<th>237</th>
		<th>47</th>
		<th>53</th>
		<th>137</th>
		<th>19</th>
		<th>7145</th>
		<th>160</th>
	</tr><tr>
		<th>Shell</th>
		<th>1</th>
		<th>104</th>
		<th>24</th>
		<th>27</th>
		<th>53</th>
		<th>11</th>
		<th>2676</th>
		<th>68</th>
	</tr><tr>
		<th>Systemd</th>
		<th>1</th>
		<th>144</th>
		<th>15</th>
		<th>0</th>
		<th>129</th>
		<th>0</th>
		<th>5907</th>
		<th>103</th>
	</tr></tbody>
	<tfoot><tr>
		<th>Total</th>
		<th>10</th>
		<th>3602</th>
		<th>624</th>
		<th>231</th>
		<th>2747</th>
		<th>811</th>
		<th>100810</th>
		<th>1891</th>
	</tr></tfoot></table>

## Future plans

1. Some features of the legacy software are still missing in this
   implementation and may be added in future updates.  These features
   include text *CAPTCHA*s, throttling, load-balancing, fail-over,
   flow control, SSH targets, and TELNET listeners.

2. When users access an SSH listener, the connecting client may supply
   a password or present public keys for authentication.  These
   authentication attempts are currently logged, but are not
   otherwise used by the proxy.  A future update may allow for
   passwords and public keys to be used for pre-authentication or to
   influence target routing.

## Compressed logs

By default, all session log files are compressed automatically when
the session terminates, and console log files are compressed when the
log rolls over (*i.e.*, when starting a new day).

When reviewing logs, administrators often need to search through all
the past data, including through the compressed files. We recommend
using [`ripgrep`](https://github.com/BurntSushi/ripgrep) (with the
`-z` option) for this task.

## Using OpenSSH host keys

If you have existing [OpenSSH](https://www.openssh.com/) Ed25519 or
RSA host keys that you want to use with the proxy, you’ll first need
to convert those keys to standard PEM format.

**NB**: These instructions *do not* include any specific details for
safe handling of key file permissions—we assume you are `root` and
that know what you’re doing!

1. Make a *copy* of the key files you wish to convert.  Be aware that
   these copies will be *overwritten* in the conversion process:

   ```sh
   cp /etc/ssh/ssh_host_rsa_key ssh_host_rsa_key.tmp
   cp /etc/ssh/ssh_host_ed25519_key ssh_host_ed25519_key.tmp
   ```

2. Convert the keys (using `ssh-keygen`) and rename them appropriately:

   ```sh
   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_rsa_key.tmp
   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_ed25519_key.tmp
   mv ssh_host_rsa_key.tmp ssh_host_rsa_key.pem
   mv ssh_host_ed25519_key.tmp ssh_host_ed25519_key.pem 
   ```

## Development

* For `proxy` development, along with the most recent version of
  [Go](https://go.dev/), you’ll also need to have a standard POSIX.1
  shell environment (at a minimum `sh`, `make`, `grep`, `awk`, &
  `sed`), and [`reuse`](https://github.com/fsfe/reuse-tool),
  [`staticcheck`](https://staticcheck.dev/),
  [`revive`](https://revive.run/),
  [`errcheck`](https://github.com/kisielk/errcheck),
  [`gofumpt`](https://github.com/mvdan/gofumpt),
  [`scc`](https://github.com/boyter/scc),
  [`codespell`](https://github.com/codespell-project/codespell), and
  [Perl](https://www.perl.org/).
* If you plan to make any changes to the [`Makefile`](Makefile) (or
  the [`.cross.sh`](.cross.sh) script), you’ll need to have the
  [ShellCheck](https://www.shellcheck.net/) and
  [`shfmt`](https://github.com/mvdan/sh) linters available.
* Additionally, all modifications to the `Makefile` and `.cross.sh`
  scripts must be tested against
  [`pdpmake`](https://frippery.org/make/)
  (with `PDPMAKE_POSIXLY_CORRECT` set) and
  [`yash`](https://magicant.github.io/yash/) to ensure POSIX
  conformance.
* While not absolutely required, it’s a good idea to have the latest
  [`golangci-lint`](https://golangci-lint.run/) installed.  We ship a
  [config file](.golangci.yml) file for it, and try to make sure that
  all the tests pass when using the most recently released version.
* It’s also recommended to (manually) use
  [`hunspell`](https://hunspell.github.io/) for spell
  checking—`codespell` doesn’t catch everything.
* The `Makefile` provides a `lint` convenience target to help you run
  all this stuff.

## Security

* The canonical home of this software is
  \<[`https://gitlab.com/dps8m/proxy`](https://gitlab.com/dps8m/proxy)\>.
* This software is intended to be **secure**.  If you find any
  security-related problems, please don’t hesitate to
  [open a GitLab Issue](https://gitlab.com/dps8m/proxy/-/issues/new)
  (or send an
  [email](mailto:contact-project+dps8m-proxy-71601954-issue-@incoming.gitlab.com)
  to the author).

## License

* The `proxy` program is made available under the terms of the
  [MIT License](https://opensource.org/license/mit), with some bundled
  example and miscellaneous files distributed under the terms of the
  [MIT No Attribution License](https://opensource.org/license/mit-0).
