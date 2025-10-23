# proxy

<!-- Copyright (c) 2025 Jeffrey H. Johnson -->
<!-- Copyright (c) 2025 The DPS8M Development Team -->
<!-- SPDX-License-Identifier: MIT -->
<!-- scspell-id: 698e77d8-6bd2-11f0-9441-80ee73e9b8e7 -->
<!-- NB: Do not modify README.md directly; modify README.md.tmpl -->

[![Go Report Card](https://goreportcard.com/badge/gitlab.com/dps8m/proxy)](https://goreportcard.com/report/gitlab.com/dps8m/proxy)
[![Pipeline Status](https://gitlab.com/dps8m/proxy/badges/master/pipeline.svg)](https://gitlab.com/dps8m/proxy/-/pipelines/)
[![CodeQL](https://github.com/johnsonjh/dps8m-proxy/actions/workflows/github-code-scanning/codeql/badge.svg)](https://github.com/johnsonjh/dps8m-proxy/actions/workflows/github-code-scanning/codeql)
[![Dependabot Updates](https://github.com/johnsonjh/dps8m-proxy/actions/workflows/dependabot/dependabot-updates/badge.svg)](https://github.com/johnsonjh/dps8m-proxy/actions/workflows/dependabot/dependabot-updates)
[![Quality Gate Status](https://sonarcloud.io/api/project_badges/measure?project=johnsonjh_dps8m-proxy&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=johnsonjh_dps8m-proxy)
[![REUSE status](https://api.reuse.software/badge/gitlab.com/dps8m/proxy)](https://api.reuse.software/info/gitlab.com/dps8m/proxy)

## Overview

The **`proxy`** program acts as a multi‑user *terminal server* and
relay 📡, accepting incoming **SSH** client connections on the
front‑end (*listeners* 👂) and proxying these connections to one or
more **TELNET** servers on the back‑end (*targets* 🎯).

> This project was originally developed to meet the needs of the
> *BAN.AI Public Access Multics* system and the
> [DPS8M Simulator](https://dps8m.gitlab.io) project, but may be
> useful to anyone who wants to offer SSH access to legacy systems.

## Features

* ✅ SSH ⟷ TELNET gateway
* ✅ Full IPv6 support
* ✅ Access control whitelist/blacklist (by IP address or CIDR block)
* ✅ Independent console and session logging (by date/time and host)
* ✅ Automatic log‑file compression (using gzip, lzip, xz, or zstandard)
* ✅ Banners for accepted, denied, and blocked connections (configurable per target)
* ✅ Session connection monitoring and idle time tracking (with optional timeouts)
* ✅ Translation of SSH `window‑change` events to TELNET NAWS messages
* ✅ Interactive connection management for administrators
* ✅ User access to TELNET features (*e.g.*, line BREAK, AYT) and statistics
* ✅ Transparent key remapping mode (translating movement keys to Emacs sequences)
* ✅ Optional support for management using `systemd` on Linux (running in a sandbox)
* ✅ Optional mDNS (Multicast DNS) DNS-SD service advertisements for listeners
* ✅ Link filtering
* ✅ Live streaming connection sharing (read‑only)
  * 🤝 Allows users to share their session with one or more viewers

## Installation

### Binaries

 * We currently publish more than 40 binaries supporting 13
   operating systems (IBM AIX, IBM i, Android, Apple macOS, Dragonfly
   BSD, FreeBSD, illumos, Linux, NetBSD, OpenBSD, Plan 9, Solaris, and
   Microsoft Windows) on 14 hardware architectures.
   * You can download pre-compiled binaries for all of these systems
     (except IBM i) from
     **[`https://dps8m.gitlab.io/proxy/`](https://dps8m.gitlab.io/proxy/)**.
   * Look [**here**](https://gitlab.com/dps8m/proxy/-/snippets) if you
     need binaries for [IBM i](https://www.ibm.com/products/ibm-i)
     (OS/400) that run under the
     [PASE](https://www.ibm.com/docs/en/i/latest?topic=i-pase-overview)
     subsystem.

### Source

A recent version of [Go](https://go.dev/) 🐹 is required to build
`proxy` from source code.

* You can clone the
  [`git` repository](https://gitlab.com/dps8m/proxy.git) 🌱 and build
  the source code using `make`:

  ```sh
  git clone https://gitlab.com/dps8m/proxy.git
  cd proxy
  make
  ```

  * If you don’t have a (POSIX) `make` available for some
    reason, then building with `go build` is sufficient.

  * A [`.cross.sh`](.cross.sh) cross‑compilation helper script is
    provided (which can be called with `make cross`) that attempts to
    build `proxy` binaries for *all* supported `GOOS` and `GOARCH`
    combinations.

* You can also install this software using `go install` 📦:

  ```sh
  go install gitlab.com/dps8m/proxy@latest
  ```

  * Installations using `go install` download the required sources,
    compile, and install the binary to `${GOEXE}/proxy` (which will
    be `${HOME}/go/bin/proxy` for most users).

## Usage

### Invocation

* The `proxy` command can be invoked with the following command‑line
  arguments:

```plaintext
DPS8M Proxy v0.1.40 (2025-Oct-23 gf5a8703) [linux/amd64]

Usage for /home/jhj/dps8m-proxy/proxy:

  --allow-root                  Allow running as root (UID 0)
  --cert-dir string             Directory containing SSH host certificates
                                    (default: current working directory)
  --cert-perm octal             Permissions (octal) for new certificate files
                                    [e.g., "600", "644"] (default 600)
  --ssh-addr strings            SSH listener address(es)
                                    [e.g., ":2222", "[::1]:8000"]
                                    (multiple allowed) (default ":2222")
  --ssh-delay float             Delay for incoming SSH connections
                                    ["0.0" to "30.0" seconds] (no default)
  --no-banner                   Disable SSH connection banner
  --telnet-host string          Default TELNET target [host:port]
                                    (default "127.0.0.1:6180")
  --alt-host string             Alternate TELNET target(s) [sshuser@host:port]
                                    (multiple allowed)
  --debug-telnet                Debug TELNET option negotiation
  --debug-server string         Enable HTTP debug server listening address
                                    [e.g., ":6060", "[::1]:6060"]
  --gops                        Enable the "gops" diagnostic agent
                                    (see https://github.com/google/gops)
  --mdns                        Enable mDNS (Multicast DNS) advertisements
                                    (i.e., Bonjour, Avahi announcements)
  --log-dir string              Base directory for logs (default "log")
  --no-log                      Disable all session logging
                                    (for console logging see "--console-log")
  --console-log string          Enable console logging ["quiet", "noquiet"]
                                    (disabled by default)
  --compress-algo string        Compression algorithm for log files
                                    ["gzip", "lzip", "xz", "zstd"]
                                    (default "gzip")
  --compress-level string       Compression level for gzip, lzip, and zstd
                                    algorithms ["fast", "normal", "high"]
                                    (default "normal")
  --no-compress                 Disable session and/or console log compression
  --log-perm octal              Permissions (octal) for new log files
                                    [e.g., "600", "644"] (default 600)
  --log-dir-perm octal          Permissions (octal) for new log directories
                                    [e.g., "755", "750"] (default 750)
  --db-file string              Path to persistent statistics storage database
                                    (disabled by default)
  --db-time uint                Elapsed seconds between database updates
                                    [0 disables periodic writes] (default 30)
  --db-perm octal               Permissions (octal) for new database files
                                    [e.g., "600", "644"] (default 600)
  --db-loglevel string          Database engine (BBoltDB) logging output level
                                    [level: "0" - "6", or "none" - "debug"]
                                    (default "error")
  --idle-max int                Maximum connection idle time allowed [seconds]
  --time-max int                Maximum connection link time allowed [seconds]
  --blacklist string            Enable blacklist [filename] (no default)
  --whitelist string            Enable whitelist [filename] (no default)
  --utc                         Use UTC (Coordinated Universal Time) for time
                                    display and timestamping in log files
  --license                     Show license terms and conditions
  --version                     Show version information
  --help                        Show this help and usage information

proxy home page (bug reports): <https://gitlab.com/dps8m/proxy/>
```

Most of these command‑line arguments are straightforward with
usage that should be obvious, and those that require demystification
are, hopefully, documented here:

* Logging of sessions is *enabled* by default.  Logging of console
  messages is *disabled* by default.

  * Console logging, if enabled, supports two modes: `quiet` and
    `noquiet`.  In `quiet` mode, all non‑fatal messages are logged
    **only** to the log file, where in `noquiet` mode, messages are
    logged to **both** the console and the log file.

  * By default, the local time zone is used for time display and
    writing log files.  Users can specify the `‑‑utc` option to use
    UTC (Coordinated Universal Time) instead.  Additionally, on
    Unix-like systems, the `TZ` environment variable is respected.

  * If the proxy fails to create log directories or files, a warning
    will be displayed on the console and the session and/or console
    logging feature *may* be (but is not guaranteed to be) disabled.
    In a future version, this behavior will be configurable (*e.g.,*
    allow to either immediately or gracefully exit on logging failure).

* Enabling the database (with the `‑‑db-file` option) persists to disk
  the connection statistics (viewable with the `s` admin console
  command) so the stats are not lost when restarting the proxy.  It
  is customary to use a name ending with the extension `db` (*e.g.,*
  `proxy.db`).

* All incoming SSH users are connected to the default TELNET target,
  unless their supplied SSH username matches an alternate target
  enabled with the `‑‑alt‑host` flag.  The alt‑host syntax is
  `sshuser@host:port`, where `sshuser` is the SSH username, and the
  `host:port` is the TELNET target.

* All users connecting with SSH are shown a banner which includes
  details such as the date and time of the session, their IP address,
  and possibly a resolved host name.  This can be disabled with
  `‑‑no‑banner`.

* The `‑‑no‑banner` command disables only those lines described above.
  It does *not* disable the file‑based banner content.  These are the
  three primary text files which can be displayed to connecting
  SSH users:

  | File        | Purpose                                                                   |
  |------------:|:--------------------------------------------------------------------------|
  | `block.txt` | Displayed before disconnecting connections matching the blacklist         |
  | `deny.txt`  | Displayed when denying target sessions (*e.g.*, during graceful shutdown) |
  | `issue.txt` | Displayed to users before their actual session with the target begins     |

  * When multiple are targets defined using the `‑‑alt‑host`
    functionality, the system will display a file that matches `‑NAME`
    before the `.txt` extension.  For example, if you have defined a
    target as  `oldunix@10.0.5.9:3333` the proxy will look for
    `block‑oldunix.txt`, `deny‑oldunix.txt`, and `issue‑oldunix.txt`
    files to serve to the connected user, before beginning their
    session with the target (via TELNET to `10.0.5.9:3333`).  If any
    of the target‑specific text files do not exist, then the standard
    files will be served.
  * To disable the file‑based banner for specific targets only, you
    can create empty files using the naming scheme described above.
    You can also remove *all* of these files if you don’t want to
    use this functionality.

* You need to start `proxy` using the `‑‑whitelist` and/or
  `‑‑blacklist` argument to enable the access control functionality.
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

* The `‑v` or `‑‑version` command shows detailed version information,
  including the versions of any embedded dependencies as well as the
  version of the Go compiler used to build the software:

```plaintext
DPS8M Proxy v0.1.40 (2025-Oct-23 gf5a8703) [linux/amd64]

+===========================+==================================+
| Component                 | Version                          |
+===========================+==================================+
| dps8m/proxy               | v0.1.40                          |
| arl/statsviz              | v0.7.2                           |
| google/gops               | v0.3.29* (2025-May-14, ga2d8f77) |
| gorilla/websocket         | v1.5.3                           |
| hashicorp/mdns            | v1.0.6                           |
| klauspost/compress        | v1.18.1                          |
| miekg/dns                 | v1.1.68                          |
| sorairolake/lzip-go       | v0.3.8                           |
| spf13/pflag               | v1.0.11* (2025-Oct-07, g6fcfbc9) |
| ulikunitz/xz              | v0.5.15                          |
| go.etcd.io/bbolt          | v1.4.3                           |
| golang.org/x/crypto       | v0.43.0                          |
| golang.org/x/net          | v0.46.0                          |
| golang.org/x/sys          | v0.37.0                          |
| golang.org/x/term         | v0.36.0                          |
| kernel.org/.../libcap/cap | v1.2.76                          |
| kernel.org/.../libcap/psx | v1.2.76                          |
| Go compiler (gc)          | v1.25.3                          |
+===========================+==================================+
```

* If you need to see additional details about the `proxy` binary,
  you can run `go version ‑m proxy`.

### Port binding

* If you want to listen on the regular SSH port of 22 (without
  running as `root`, which is strongly discouraged), on Linux systems
  you can use `setcap` to allow the proxy to bind to privileged ports:

  ```sh
  sudo setcap 'cap_net_bind_service=+ep' "/path/to/proxy"
  ```

* If this is necessary (*i.e.*, a non‑root user on Linux is attempting
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
  * `s` — Show connection statistics
  * `l` — List active connections
  * `k` — Kill a connection
  * `d` — Deny new connections
  * `r` — Reload access control lists
  * `q` — Graceful shutdown
  * `Q` — Immediate shutdown (also via `^C`)
[]()

[]()
Most of these admin console commands are straightforward and should
be self‑explanatory, although there are a few options that merit
further clarification:

* When the **Graceful shutdown** mode is active, all new connections
  are denied (and are served an appropriate `deny.txt` banner).  Once
  all clients have disconnected, the proxy software will exit.  Note
  that new *monitoring sessions* can still connect to observe active
  users, as these sessions are automatically closed when their
  observation target disconnects.

* When the **Deny new connections** mode is active, all new connections
  are denied (and are served an appropriate `deny.txt` banner).  In
  addition, *all logging* of new connection attempts, including any
  denied and/or rejected connections, is suppressed.  This can be
  useful when the logs or admin console are overwhelmed with activity
  (such as during bot attacks, busy periods, or when troubleshooting).
  Activating this mode can help reduce console noise, making it easier
  to perform admin actions such as viewing the configuration, or
  listing and killing active connections.

* The `k` command, which kills a connection, takes either a
  *Session ID* as an argument (shown when listing active connections
  with the `l` command) or `*`, which kills *all* active connections.

If it is detected that you have a UTF-8 capable terminal, then some
console output will be augmented with icons or emoji glyphs (and in
a future version, UTF-8 box drawing symbols will be used for drawing
tables).

### Signals

* The proxy also acts on the following signals (on systems where
  signals are supported):

  |      Signal | Action                                                             |
  |------------:|:-------------------------------------------------------------------|
  |    `SIGINT` | Enables the **Immediate shutdown** mode                            |
  |   `SIGQUIT` | Enables the **Immediate shutdown** mode                            |
  |   `SIGUSR1` | Enables the **Graceful shutdown** mode                             |
  |   `SIGUSR2` | Enables the **Deny new connections** mode                          |
  |    `SIGHUP` | Reloads *access control lists* (`‑‑whitelist`, `‑‑blacklist`)      |
  | `SIGDANGER` | Attempts to immediately free as much memory as possible (AIX‑only) |

### Management with systemd

If you’re running the proxy on a Linux system, you can use `systemd`
to manage the service (while maintaining access to the interactive
admin console).

* The `systemd` integration requires `systemd` version **247** or
  later (Nov. 2020), and a *recent* version of
  [`tmux`](https://github.com/tmux/tmux).
[]()

[]()
* With minor changes 🔧 to the unit file, this setup can also work
  with `systemd` as old as version **229** (Feb. 2016).
* See the detailed instructions in the
  [`systemd/dps8m‑proxy.service`](systemd/dps8m-proxy.service)
  file for full installation instructions.

### User interaction

Users connected via SSH can send `^]` (*i.e.*, `Control + ]`) during
their session to access the following following TELNET control
features:

* `]` — sends a literal `Control‑]` to the target TELNET host

* `0` — sends a literal `NUL` to the target TELNET host

* `A` — sends an IAC `AYT` (*Are You There?*) to the target TELNET host

* `B` — sends an IAC `BREAK` signal to the target TELNET host

* `I` — sends an IAC `INTERRUPT` signal to the target TELNET host

* `K` — toggles the transparent key remapping mode, which translates
  modern `xterm`/`VT320` movement key inputs to Emacs sequences:

  |             Input | Output        |
  |------------------:|:--------------|
  | `Control + Up`    | `Escape, [`   |
  | `Control + Down`  | `Escape, ]`   |
  | `Control + Right` | `Escape, f`   |
  | `Control + Left`  | `Escape, b`   |
  | `Home`            | `Control + A` |
  | `Delete`          | `Control + D` |
  | `End`             | `Control + E` |
  | `Up`              | `Escape + v`  |
  | `Down`            | `Control + V` |
  | `Up`              | `Control + P` |
  | `Down`            | `Control + N` |
  | `Right`           | `Control + F` |
  | `Left`            | `Control + B` |

* `N` — sends an IAC `NOP` (*No Operation*) to the target TELNET host

* `S` — displays the status the session, sharing information, and some
  statistics:

  ```plaintext
  >> LNK ‑ The username '_gRSyWHxPcMp2MWvtmWWF' can be used to share this session.
  >> SSH ‑ in:   58 B,   out: 4.82 KiB, in rate:   4 B/s, out rate: 381 B/s
  >> NVT ‑ in: 4.82 KiB, out:   57 B,   in rate: 381 B/s, out rate:   4 B/s
  >> LNK ‑ link time: 13s (Emacs keymap enabled)
  ```

* `X` — disconnects from the target TELNET host (and ends the SSH
  session)

### Connection sharing

* The user can share 🤝 the username presented above with others,
  allowing the session to be viewed live 👀 (read‑only) by one or more
  viewers:

  ```sh
  $ ssh _gRSyWHxPcMp2MWvtmWWF@proxybox

  CONNECTION from remote.com [18.17.16.15] started at 2025/07/15 08:22:55.
  This is a READ‑ONLY shared monitoring session.
  Send Control‑] to disconnect.
  ```

## Compressed logs

* By default, all session log files are compressed 🗜️ automatically
  when the session terminates, and console log files are compressed
  when the log rolls over (*i.e.*, when starting a new day).

* When reviewing logs, administrators often need to search through all
  the past data, including through the compressed files. We recommend
  using [`ripgrep`](https://github.com/BurntSushi/ripgrep) (with the
  `‑z` option) for this task.

## Using OpenSSH host keys

If you have existing [OpenSSH](https://www.openssh.com/) Ed25519, RSA,
or ECDSA host keys that you want to use with the proxy, you’ll first
need to convert those keys to standard PEM format.

🚨 **NB**: These instructions *do not* include any specific details
for safe handling of key file permissions—we assume you are `root`
and that you know what you’re doing!

1. Make a *copy* of the key files you wish to convert.  Be aware that
   these copies will be *overwritten* in the conversion process:

   ```sh
   cp /etc/ssh/ssh_host_ed25519_key ssh_host_ed25519_key.tmp
   cp /etc/ssh/ssh_host_rsa_key ssh_host_rsa_key.tmp
   cp /etc/ssh/ssh_host_ecdsa_key ssh_host_ecdsa_key.tmp
   ```

2. Convert the keys (using `ssh‑keygen`) and rename them appropriately:

   ```sh
   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_ed25519_key.tmp
   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_rsa_key.tmp
   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_ecdsa_key.tmp
   mv ssh_host_ed25519_key.tmp ssh_host_ed25519_key.pem
   mv ssh_host_rsa_key.tmp ssh_host_rsa_key.pem
   mv ssh_host_ecdsa_key.tmp ssh_host_ecdsa_key.pem
   ```

## History

This is a from‑scratch re‑implementation (in [Go](https://go.dev/) 🐹)
of an older legacy program of the same name.

The original software used a multi‑process architecture and consisted
of nearly **15,000 lines** of haphazardly constructed code: ≅14,000
lines of mostly [C‑Kermit](https://www.kermitproject.org/) 🐸 (*yes,
the
[programming language](https://www.kermitproject.org/ckscripts.html)*)
and [`ksh93`](https://github.com/ksh93/ksh) 🐚 (along with some C 💻,
Python 🐍, and Perl 🐪) which was difficult to maintain, configure,
and securely install.

This new implementation uses many lightweight *Goroutines* 🚀 instead
of spawning multiple processes, resulting in significantly improved
performance and reduced system overhead.

## Code statistics

The new `proxy` program is considerably simpler than its legacy
predecessor (code statistics 📈 provided by
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
<th>16</th>
<th>7608</th>
<th>1589</th>
<th>396</th>
<th>5623</th>
<th>1334</th>
<th>184597</th>
<th>3367</th>
</tr><tr>
<th>Shell</th>
<th>3</th>
<th>309</th>
<th>74</th>
<th>84</th>
<th>151</th>
<th>21</th>
<th>9005</th>
<th>154</th>
</tr><tr>
<th>Makefile</th>
<th>1</th>
<th>452</th>
<th>73</th>
<th>79</th>
<th>300</th>
<th>87</th>
<th>15202</th>
<th>308</th>
</tr><tr>
<th>Markdown</th>
<th>1</th>
<th>556</th>
<th>105</th>
<th>0</th>
<th>451</th>
<th>0</th>
<th>26415</th>
<th>436</th>
</tr><tr>
<th>Systemd</th>
<th>1</th>
<th>209</th>
<th>35</th>
<th>107</th>
<th>67</th>
<th>0</th>
<th>7595</th>
<th>135</th>
</tr><tr>
<th>YAML</th>
<th>1</th>
<th>78</th>
<th>6</th>
<th>10</th>
<th>62</th>
<th>0</th>
<th>3378</th>
<th>69</th>
</tr></tbody>
<tfoot><tr>
<th>Total</th>
<th>23</th>
<th>9212</th>
<th>1882</th>
<th>676</th>
<th>6654</th>
<th>1442</th>
<th>246192</th>
<th>4452</th>
</tr></tfoot></table>

## Future plans

* Some features of the legacy software are still missing in this
  implementation and may be added in future updates.  These features
  include text *CAPTCHA*s, load‑balancing, fail‑over,
  [flow control](https://www.rfc-editor.org/rfc/rfc1372), SSH
  targets, and TELNET listeners.
* When users access an SSH listener, the connecting client may supply
  a password or present public keys for authentication.  These
  authentication attempts are currently logged, but are not
  otherwise used by the proxy.  A future update may allow for
  passwords and public keys to be used for pre‑authentication or to
  influence target routing.
[]()

[]()
* While TELNET protocol support will improve in the future, there are
  no plans to support the
  [linemode](https://www.rfc-editor.org/rfc/rfc1184),
  [environment](https://www.rfc-editor.org/rfc/rfc1572),
  [authentication](https://www.rfc-editor.org/rfc/rfc2941),
  or [encryption](https://www.rfc-editor.org/rfc/rfc2946)
  features at this time.
  * If you need these features, you should look into
    [C‑Kermit](https://kermitproject.org/) or
    [Kermit 95](https://davidrg.github.io/ckwin/).
  * Although directly executing programs isn’t something on the
    roadmap, it’s not difficult to use `socat` creatively to connect
    C‑Kermit to the proxy (*i.e.*,
    `socat TCP‑LISTEN:9876,fork,reuseaddr,nodelay EXEC:kermit,pty,setsid,echo=0,rawer,opost=1,icrnl=1,onlcr,cread`).
  * ⚠️ Be aware that doing this *securely*—safe for public usage—is
    more involved than one might imagine.  *Safely* configuring the
    proxy for this type of operation is possible, but beyond the scope
    of this documentation.

## Development

### Required

* For `proxy` development, along with the most recent version of
  [Go](https://go.dev/), you’ll also need to have a standard POSIX.1
  shell environment (at a minimum `sh`, `make`, `grep`, `awk`, &
  `sed`), and [`reuse`](https://github.com/fsfe/reuse-tool),
  [`staticcheck`](https://staticcheck.dev/),
  [`gopls`](https://go.dev/gopls/),
  [`revive`](https://revive.run/),
  [`errcheck`](https://github.com/kisielk/errcheck),
  [`gofumpt`](https://github.com/mvdan/gofumpt),
  [`govulncheck`](https://go.googlesource.com/vuln),
  [`scc`](https://github.com/boyter/scc),
  [`scspell`](https://github.com/myint/scspell),
  [`codespell`](https://github.com/codespell-project/codespell), and
  [Perl](https://www.perl.org/).
* If you plan to make any changes to the [`Makefile`](Makefile) (or
  the [`.cross.sh`](.cross.sh) script), you’ll need to have the
  [ShellCheck](https://www.shellcheck.net/) and
  [`shfmt`](https://github.com/mvdan/sh) linters available.
* Additionally, all modifications to the [`Makefile`](Makefile) and
  [`.cross.sh`](.cross.sh) scripts must be tested against
  [`pdpmake`](https://frippery.org/make/)
  (with `PDPMAKE_POSIXLY_CORRECT` set) and
  [`yash`](https://magicant.github.io/yash/) to ensure POSIX
  conformance.
* The [`Makefile`](Makefile) provides a `lint` convenience target to
  help you run all this.  You can also examine our
  [`.gitlab-ci.yml`](.gitlab-ci.yml) file.  There is also a
  convenience script, `.lintsetup.sh`, to help install the Go-based
  linters, and the Python-based linters can be installed via `pip`
  (*i.e.*, `pip install --upgrade scspell3k codespell reuse`).

### Recommended

* While not absolutely required, it’s a good idea to have the latest
  [`golangci-lint`](https://golangci-lint.run/) (v2) installed.  We
  ship a [config file](.golangci.yml) file for it, and try to make
  sure that all the tests pass when using the most recently released
  version.
* It’s also recommended to (*manually*) use
  [`hunspell`](https://hunspell.github.io/) for spell
  checking—in addition to using `codespell` and `scspell`.

## Security

* The canonical home of this software is
  [`https://gitlab.com/dps8m/proxy`](https://gitlab.com/dps8m/proxy),
  with a mirror on [GitHub](https://github.com/johnsonjh/dps8m-proxy/).
* This software is intended to be **secure** 🛡️.
* If you find any security‑related problems, please don’t hesitate to
  [open a GitLab Issue](https://gitlab.com/dps8m/proxy/-/issues/new)
  (or send an
  [email](mailto:contact-project+dps8m-proxy-71601954-issue-@incoming.gitlab.com)
  to the author).

## Licenses

* The `proxy` program is made available under the terms of the
  [MIT License](https://opensource.org/license/mit).
* Some bundled example and miscellaneous files distributed under the
  terms of the
  [MIT No Attribution License](https://opensource.org/license/mit-0).
* All direct and indirect dependencies are licensed under permissive
  open-source licenses:
  |                                                                     Dependency | License                                                     |
  |-------------------------------------------------------------------------------:|:------------------------------------------------------------|
  |                                [arl/statsviz](https://github.com/arl/statsviz) | [MIT](https://opensource.org/license/mit)                   |
  |                              [etcd-io/bbolt](https://github.com/etcd-io/bbolt) | [MIT](https://opensource.org/license/mit)                   |
  |                            [hashicorp/mdns](https://github.com/hashicorp/mdns) | [MIT](https://opensource.org/license/mit)                   |
  |                  [sorairolake/lzip-go](https://github.com/sorairolake/lzip-go) | [MIT](https://opensource.org/license/mit)                   |
  |                            [uber-go/goleak](https://github.com/uber-go/goleak) | [MIT](https://opensource.org/license/mit)                   |
  |                      [gorilla/websocket](https://github.com/gorilla/websocket) | [BSD-2-Clause](https://opensource.org/license/bsd-2-clause) |
  |                                  [google/gops](https://github.com/google/gops) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  |                    [klauspost/compress](https://github.com/klauspost/compress) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  | [libcap/cap](https://pkg.go.dev/kernel.org/pub/linux/libs/security/libcap/cap) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  | [libcap/psx](https://pkg.go.dev/kernel.org/pub/linux/libs/security/libcap/psx) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  |                                      [miekg/dns](https://github.com/miekg/dns) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  |                                  [spf13/pflag](https://github.com/spf13/pflag) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  |                                [ulikunitz/xz](https://github.com/ulikunitz/xz) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  |                                        [x/crypto](https://golang.org/x/crypto) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  |                                              [x/mod](https://golang.org/x/mod) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  |                                              [x/net](https://golang.org/x/net) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  |                                            [x/sync](https://golang.org/x/sync) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  |                                              [x/sys](https://golang.org/x/sys) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  |                                            [x/term](https://golang.org/x/term) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  |                                          [x/tools](https://golang.org/x/tools) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |

<!-- vim: set ft=markdown expandtab cc=72 : -->
<!-- EOF -->
