# proxy

<!-- Copyright (c) 2025-2026 Jeffrey H. Johnson -->
<!-- Copyright (c) 2025-2026 The DPS8M Development Team -->
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
* ✅ Optional conversion of legacy host character mappings to UTF-8
* ✅ Optional mDNS (Multicast DNS) DNS-SD service advertisements for listeners
* ✅ Optional link filtering
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

  * *Optionally*, for most UNIX-like systems, you can execute
    `make install` (or `make install-strip`) to install the proxy for
    system-wide usage:

    ```sh
    make install
    ```

    * The installation targets respect both the `PREFIX`
      environment variable (which defaults to `/usr/local`) and the
      `DESTDIR` environment variable (used by package maintainers to
      install the software to a staging directory).

  * The [`.cross.sh`](.cross.sh) cross‑compilation helper script
    is provided (which can be called with `make cross`) that
    attempts to build `proxy` binaries for *all* supported `GOOS`
    and `GOARCH` combinations (except some specific Android builds,
    which are handled by [`.cross-android.sh`](.cross-android.sh)
    for building the Android binaries that require the
    [Android NDK](https://developer.android.com/ndk)).

  * If you **don’t** have a (POSIX) `make` available for some
    reason, then building with `go build` (or `go install`) will
    likely be sufficient for most end-users.

* To install the software using `go install` 📦:

  ```sh
  env GOTOOLCHAIN=auto go install -v gitlab.com/dps8m/proxy@latest
  ```

  * Installations using the `go install` method will install the
    appropriate Go toolchain (if needed), download the `proxy` sources,
    compile them, and install the `proxy` binary to `${GOEXE}/proxy`
    (which will be `${HOME}/go/bin/proxy` for most users).

* For users requiring completely offline builds, we provide a
  [source archive](https://dps8m.gitlab.io/proxy/proxy.src.tar.gz)
  for the current release which
  [vendors](https://go.dev/ref/mod#vendoring) all dependencies.

## Usage

### Invocation

* The `proxy` command can be invoked with the following command‑line
  arguments:

```plaintext
DPS8M Proxy v1.1.12 (2026-May-04 g0354d69) [linux/amd64]

Usage for proxy:

  --allow-root                  Allow running as root (UID 0)
  --cert-dir <string>           Directory containing SSH host certificates
                                    (default: current working directory)
  --cert-perm <octal>           Permissions (octal) for new certificate files
                                    [e.g., "600", "644"] (default 600)
  --cert-rsa-bits <uint>        RSA key size in bits for new certificates
                                    ["1024" to "4096"] (default 2048)
  --cert-ecdsa-bits <uint>      ECDSA key size in bits for new certificates
                                    ["256", "384", "521"] (default 256)
  --ssh-addr <string>           SSH listener address(es)
                                    [e.g., ":2222", "[::1]:8000"]
                                    (multiple allowed) (default ":2222")
  --ssh-delay <float>           Delay for incoming SSH connections
                                    ["0.0" to "30.0" seconds] (no default)
  --no-banner                   Disable the user SSH connection banner
  --no-menu                     Disable the user SSH 'Control-]' menu
  --telnet-host <string>        Default TELNET target [host:port
                                   or socket path] (default "127.0.0.1:6180")
  --alt-host <string>           Alternate TELNET target(s) [sshuser@host:port
                                    or "sshuser@/path"] (multiple allowed)
  --iconv <string>              Character map conversion of text to UTF-8
                                    [e.g., "IBM Code Page 437"] (no default)
  --debug-telnet                Debug TELNET option negotiation
  --debug-server <string>       Enable HTTP debug server listening address
                                    [e.g., ":6060", "[::1]:6060"]
  --no-filter                   Disable link filtering of NULL characters
  --no-sanitize                 Disable ASCII sanitization of error messages
                                    (allowing non-ASCII error reports via SSH)
  --gops                        Enable the "gops" diagnostic agent
                                    (see https://github.com/google/gops)
  --mdns                        Enable mDNS (Multicast DNS) advertisements
                                    (i.e., Bonjour, Avahi announcements)
  --keymap                      Enable Emacs keymapping mode by default
  --log-dir <string>            Base directory for logs (default "log")
  --no-log                      Disable all session logging
                                    (for console logging see "--console-log")
  --no-console                  Disable the interactive admin console
  --console-log <string>        Enable console logging ["quiet", "noquiet"]
                                    (disabled by default)
  --compress-algo <string>      Compression algorithm for log files
                                    ["gzip", "lzip", "xz", "zstd"]
                                    (default "gzip")
  --compress-level <string>     Compression level for gzip, lzip, and zstd
                                    ["fast", "normal", "high"]
                                    (default "normal")
  --no-compress                 Disable session and/or console log compression
  --log-perm <octal>            Permissions (octal) for new log files
                                    [e.g., "600", "644"] (default 600)
  --log-dir-perm <octal>        Permissions (octal) for new log directories
                                    [e.g., "750", "755"] (default 750)
  --db-file <string>            Path to persistent statistics storage database
                                    (disabled by default)
  --db-time <uint>              Elapsed seconds between database updates
                                    [0 disables periodic writes] (default 30)
  --db-perm <octal>             Permissions (octal) for new database files
                                    [e.g., "600", "644"] (default 600)
  --db-loglevel <string>        Database engine (BBoltDB) logging output level
                                    [level: "0" - "6", or "none" - "debug"]
                                    (default "error")
  --idle-max <uint>             Maximum connection idle time allowed [seconds]
  --idle-def-max <uint>         Maximum connection idle time allowed
                                    for only the default target [seconds]
  --time-max <uint>             Maximum connection link time allowed [seconds]
  --time-def-max <uint>         Maximum connection link time allowed
                                    for only the default target [seconds]
  --blacklist <string>          Enable blacklist [filename] (no default)
  --whitelist <string>          Enable whitelist [filename] (no default)
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
    In a future version, this behavior may be configurable (*e.g.,*
    to allow either immediately or gracefully exiting on logging
    failures).

* Enabling the database (with the `‑‑db-file` option) persists to disk
  the connection statistics (viewable with the `s` admin console
  command) so the stats are not lost when restarting the proxy.  It
  is customary to use a name ending with the extension `db` (*e.g.,*
  `proxy.db`).

* The default TELNET target for `--telnet-host` is specified as a
  `host:port` or `path` (for connecting to a UNIX domain socket).
  Valid examples include `hostname:23`, `1.2.3.4:2323`,
  `[2607:f8b0:4008:805::2000]:23`, `./socket`, and `/path/socket`.

* All incoming SSH users are connected to the default TELNET target,
  unless their supplied SSH username matches an alternate target
  enabled with the `‑‑alt‑host` flag.  The alt‑host syntax is
  `sshuser@host:port` or `sshuser@path`, where `sshuser` is the SSH
  username, and the `host:port` (or `path`, an absolute or relative
  path to a UNIX domain socket) is the TELNET target.

* All users connecting with SSH are shown a banner which includes
  details such as the date and time of the session, their IP address,
  and possibly a resolved host name.  This can be disabled with
  `‑‑no‑banner`.

* The `‑‑no‑banner` option disables only those lines described above.
  It does *not* disable the file‑based banner content.  These are the
  three primary text files which can be displayed to connecting
  SSH users:

  | File        | Purpose                                                                   |
  |------------:|:--------------------------------------------------------------------------|
  | `block.txt` | Displayed before disconnecting connections matching the blacklist         |
  | `deny.txt`  | Displayed when denying target sessions (*e.g.*, during graceful shutdown) |
  | `issue.txt` | Displayed to users before their actual session with the target begins     |

  * When multiple targets are defined using the `‑‑alt‑host`
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

* The `--no-filter` option disables link filtering of NULL characters.
  This is required to use the ZMODEM inline file transfer protocol
  or other host applications that use NULL-terminated packet sequences.

* The `--iconv` option enables legacy character map conversion of
  TELNET text to UTF-8, and takes the name of the legacy mapping.

  * This option currently applies to all targets and is most useful
    to administrators of specific legacy systems such as DOS-based
    bulletin board systems.

  * *Only data received from the TELNET target is translated.*
    Transmitted data is passed as-is.

  * The following character maps are supported: `"IBM Code Page 037"`, `"IBM Code Page 437"`, `"IBM Code Page 850"`, `"IBM Code Page 852"`, `"IBM Code Page 855"`, `"IBM Code Page 860"`, `"IBM Code Page 862"`, `"IBM Code Page 863"`, `"IBM Code Page 865"`, `"IBM Code Page 866"`, `"IBM Code Page 1047"`, `"IBM Code Page 1140"`, `"ISO 8859-1"`, `"ISO 8859-2"`, `"ISO 8859-3"`, `"ISO 8859-4"`, `"ISO 8859-5"`, `"ISO 8859-6"`, `"ISO-8859-6E"`, `"ISO-8859-6I"`, `"ISO 8859-7"`, `"ISO 8859-8"`, `"ISO-8859-8E"`, `"ISO-8859-8I"`, `"ISO 8859-9"`, `"ISO 8859-10"`, `"ISO 8859-13"`, `"ISO 8859-14"`, `"ISO 8859-15"`, `"ISO 8859-16"`, `"KOI8-R"`, `"KOI8-U"`, `"Macintosh"`, `"Macintosh Cyrillic"`, `"Windows 874"`, `"Windows 1250"`, `"Windows 1251"`, `"Windows 1252"`, `"Windows 1253"`, `"Windows 1254"`, `"Windows 1255"`, `"Windows 1256"`, `"Windows 1257"`, `"Windows 1258"`, `"Windows Code Page 858"`, `"X-User-Defined"`.

  * String matching is *fuzzy* and most commonly-used abbreviations
    are supported (*e.g.*, `--iconv "CP437"`).

  * To print the list of supported character maps, pass `help`
    (or any other illegal value, *e.g.*, `--iconv "help"`).

* You need to start `proxy` using the `‑‑whitelist` and/or
  `‑‑blacklist` argument to enable the access control functionality.
  If *only* the whitelist is enabled, then all connections will be
  denied by default.  Note that if *only* the blacklist is enabled, it
  will be impossible to exempt individual IP addresses within a range
  that has been blocked.  It is recommended that you enable *both*
  lists when using the access control features.

  * The format of the whitelist and blacklist is an IPv4 or IPv6
    address (*e.g.*, `23.215.0.138`, `2600:1406:bc00:53::b81e:94ce`),
    or a CIDR block (*e.g.*, `123.45.0.0/17` which covers `123.45.0.0`
    to `123.45.127.255`, or `2600:1408:ec00:36::/64` covering
    `2600:1408:ec00:36:0000:0000:0000:0000` to
    `2600:1408:ec00:36:ffff:ffff:ffff:ffff`), one item per line.

  * The whitelist always takes precedence over the blacklist.
    If an address is allowed due to a whitelist match that would
    have otherwise been blocked by the blacklist, it is tagged as
    `EXEMPTED` in the logs.

* The `‑‑version` command shows detailed version information, which
  includes the versions of any embedded dependencies as well as the
  name and version of the Go toolchain used to build the software:

```plaintext
DPS8M Proxy v1.1.12 (2026-May-04 g0354d69) [linux/amd64]

+===========================+==================================+
| Component                 | Version                          |
+===========================+==================================+
| dps8m/proxy               | v1.1.12                          |
| arl/statsviz              | v0.8.0                           |
| google/gops               | v0.3.29                          |
| gorilla/websocket         | v1.5.3                           |
| hashicorp/mdns            | v1.0.6                           |
| klauspost/compress        | v1.18.6                          |
| miekg/dns                 | v1.1.72                          |
| sorairolake/lzip-go       | v0.3.8                           |
| spf13/pflag               | v1.0.11* (2026-May-04, gee87ca5) |
| ulikunitz/xz              | v0.5.15                          |
| go.etcd.io/bbolt          | v1.4.3                           |
| golang.org/x/crypto       | v0.50.0                          |
| golang.org/x/net          | v0.53.0                          |
| golang.org/x/sys          | v0.43.0                          |
| golang.org/x/term         | v0.42.0                          |
| golang.org/x/text         | v0.36.0                          |
| kernel.org/.../libcap/cap | v1.2.78                          |
| kernel.org/.../libcap/psx | v1.2.78                          |
| Go compiler (gc)          | v1.26.2                          |
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

* Note that some Android distributions restrict usage of ports
  below 8000.

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
a future version, UTF-8 box drawing symbols may be used for drawing
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
their session to access the following TELNET control features:

* `]` — sends a literal `Control‑]` to the target TELNET host

* `0` — sends a literal `NUL` to the target TELNET host

* `A` — sends an IAC `AYT` (*Are You There?*) to the target TELNET host

* `B` — sends an IAC `BREAK` signal to the target TELNET host

* `C` — toggles the conversion of legacy host character mappings to
  UTF-8 (if enabled via the `--iconv` option)

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
  | `Page Up`         | `Escape + v`  |
  | `Page Down`       | `Control + V` |
  | `Up`              | `Control + P` |
  | `Down`            | `Control + N` |
  | `Right`           | `Control + F` |
  | `Left`            | `Control + B` |

* `N` — sends an IAC `NOP` (*No Operation*) to the target TELNET host

* `S` — displays the status of the session, sharing information, and
  some statistics:

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
   mv ssh_host_ed25519_key.tmp ssh_host_ed25519_key.pem

   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_rsa_key.tmp
   mv ssh_host_rsa_key.tmp ssh_host_rsa_key.pem

   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_ecdsa_key.tmp
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
<th>21</th>
<th>10057</th>
<th>2132</th>
<th>616</th>
<th>7309</th>
<th>1755</th>
<th>239304</th>
<th>4397</th>
</tr><tr>
<th>Shell</th>
<th>4</th>
<th>440</th>
<th>100</th>
<th>113</th>
<th>227</th>
<th>34</th>
<th>12982</th>
<th>209</th>
</tr><tr>
<th>Makefile</th>
<th>1</th>
<th>598</th>
<th>87</th>
<th>94</th>
<th>417</th>
<th>182</th>
<th>21023</th>
<th>358</th>
</tr><tr>
<th>Markdown</th>
<th>1</th>
<th>637</th>
<th>126</th>
<th>0</th>
<th>511</th>
<th>0</th>
<th>29859</th>
<th>498</th>
</tr><tr>
<th>Systemd</th>
<th>1</th>
<th>209</th>
<th>35</th>
<th>107</th>
<th>67</th>
<th>0</th>
<th>7605</th>
<th>135</th>
</tr><tr>
<th>YAML</th>
<th>1</th>
<th>86</th>
<th>6</th>
<th>10</th>
<th>70</th>
<th>0</th>
<th>4308</th>
<th>77</th>
</tr></tbody>
<tfoot><tr>
<th>Total</th>
<th>29</th>
<th>12027</th>
<th>2486</th>
<th>940</th>
<th>8601</th>
<th>1971</th>
<th>315081</th>
<th>5656</th>
</tr></tfoot></table>


## Changes

* The [`CHANGELOG.md`](CHANGELOG.md) file summarizes the most important
  changes in each version.
* If you are looking for more details, you can use the GitLab
  [Repository graph](https://gitlab.com/dps8m/proxy/-/network/master)
  to see all the commits for each release.

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
    roadmap, it’s not difficult to use
    [`socat`](https://repo.or.cz/socat.git) creatively to connect
    C‑Kermit to the proxy using a UNIX domain socket (*i.e.*,
    `socat UNIX‑LISTEN:socket,fork,reuseaddr EXEC:kermit,pty,setsid,echo=0,rawer,opost=1,icrnl=1,onlcr,cread`).
  * ⚠️ Be aware that doing this *securely*—safe for public usage—is
    more involved than one might imagine.  *Safely* configuring the
    proxy for this type of operation is possible, but beyond the scope
    of this documentation.

## Development

### Required

* For `proxy` development, along with the most recent version of
  [Go](https://go.dev/), you’ll also need to have a standard POSIX.1
  shell environment (at a minimum `sh`, `make`, `diff`, `grep`, `awk`,
  & `sed`), and [`reuse`](https://github.com/fsfe/reuse-tool),
  [`staticcheck`](https://staticcheck.dev/),
  [`gopls`](https://go.dev/gopls/),
  [`revive`](https://revive.run/),
  [`errcheck`](https://github.com/kisielk/errcheck),
  [`gofumpt`](https://github.com/mvdan/gofumpt),
  [`govulncheck`](https://go.googlesource.com/vuln),
  [NilAway](https://github.com/uber-go/nilaway),
  [`scc`](https://github.com/boyter/scc),
  [`scspell`](https://github.com/myint/scspell),
  and [`codespell`](https://github.com/codespell-project/codespell).
* If you plan to make any changes to the [`Makefile`](Makefile) (or
  [`.cross.sh`](.cross.sh) and other scripts), you’ll need to have the
  [ShellCheck](https://www.shellcheck.net/) and
  [`shfmt`](https://github.com/mvdan/sh) linters available.
* Additionally, all modifications to the [`Makefile`](Makefile) and
  [`.cross.sh`](.cross.sh) and other scripts must be tested against
  [`pdpmake`](https://frippery.org/make/)
  (with `PDPMAKE_POSIXLY_CORRECT` set) and
  [`yash`](https://magicant.github.io/yash/) to ensure POSIX
  conformance.
* The [`Makefile`](Makefile) provides a `lint` convenience target to
  help you run all this.  You can also examine our
  [`.gitlab-ci.yml`](.gitlab-ci.yml) file.  There is also a
  convenience script, [`.lintsetup.sh`](.lintsetup.sh), to help
  install the Go-based linters, and the Python-based linters can be
  installed via `pip` (*i.e.*,
  `pip install --upgrade scspell3k codespell reuse`).

### Recommended

* Source code tags are generated using
  [`gogtags`](https://github.com/juntaki/gogtags) and
  [`gotags`](https://github.com/jstemmer/gotags)
  (or [`universal-ctags`](https://ctags.io)) if installed.
* While not absolutely required, it’s a good idea to have the latest
  [`golangci-lint`](https://golangci-lint.run/) (v2) installed.  We
  ship a [config file](.golangci.yml) file for it, and try to make
  sure that all the tests pass when using both the latest `git`
  version as well as the most recently released version.
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
* All direct, indirect, and test dependencies are licensed under
  permissive open-source licenses:
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
  |                                            [x/text](https://golang.org/x/text) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |
  |                                          [x/tools](https://golang.org/x/tools) | [BSD-3-Clause](https://opensource.org/license/bsd-3-clause) |

<!--
Local Variables:
mode: markdown
End:
-->
<!-- vim: set ft=markdown expandtab cc=72 : -->
<!-- EOF -->
