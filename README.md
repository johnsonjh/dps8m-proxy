<!-- Copyright (c) 2025 Jeffrey H. Johnson -->
<!-- Copyright (c) 2025 The DPS8M Development Team -->
<!-- SPDX-License-Identifier: MIT -->
<!-- vim: set ft=markdown expandtab cc=72 : -->
<!-- NB: Do not modify README.md directly; modify README.md.tmpl -->
# dps8m-proxy

[![Go Report Card](https://goreportcard.com/badge/gitlab.com/dps8m/proxy)](https://goreportcard.com/report/gitlab.com/dps8m/proxy)

## Overview

The **`proxy`** (or **`dps8m-proxy`**) program acts as a multi-user
*terminal server* and proxy, accepting incoming **SSH** connections on
the front-end (*listeners*) and proxying these connections to one or
more **TELNET** connections on the back-end (*targets*).

This project was originally developed to meet the needs of the
**BAN.AI Public Access Multics** system and the
[DPS8M Simulator](https://dps8m.gitlab.io) project, but may be useful
to anyone who wants to needs to offer SSH access to legacy systems.

## Features

* ✅ **SSH**⟷**TELNET** gateway
* ✅ Full IPv6 support
* ✅ Access control whitelist/blacklist (by IP address or CIDR block)
* ✅ Independent console and session logging (by date/time and host)
* ✅ Automatic logfile compression (gzip, xz, zstandard)
* ✅ Banners for accepted, denied, and blocked connections (configurable per target)
* ✅ Session connection monitoring and idle time tracking (with optional timeouts)
* ✅ Interactive connection management for administrators
* ✅ User access to **TELNET** features (*e.g.*, line BREAK, AYT) and statistics
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
  the source code with `make`:

  ```sh
  git clone https://gitlab.com/dps8m/proxy.git
  cd proxy
  make
  ```

### Invocation

* The proxy can be invoked with the following command-line arguments:

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

Most of these command-line arguments are straightforward and should 
be obvious.  Those that require demystification are, hopefully,
documented here:

* Logging of sessions is *enabled* by default.  Logging of console
  messages is *disabled* by default.  Console logging, if enabled,
  supports two modes: `quiet` and `noquiet`.  In `quiet` mode, all
  non-fatal messages are logged **only** to the log file, where in
  `noquiet` mode, messages are logged to both the console and the log
  file.

* All incoming user are connected to the default TELNET target, unless
  their connection matches an alternate target enabled with the
  `--alt-host` flag.  The alt-host syntax is `sshuser@host:port`, where
  `sshuser` is the SSH username, and the `host:port` is the TELNET
  target.

* All users connecting are shown a banner which includes details such
  as the date and time of the session, their IP address, and possibly
  a resolved host name.  This can be disabled with `--no-banner`.

* There are three text files which can be displayed to connecting
  users.  These are:

  | File        | Purpose                                                                   |
  :-------------:---------------------------------------------------------------------------:
  | `block.txt` | Displayed before disconnecting connections matching the blacklist         |
  | `deny.txt`  | Displayed when denying target sessions (*e.g.,* during graceful shutdown) |
  | `issue.txt` | Displayed to users before they the session with the target begins         |

  * When multiple targets defined using the `--alt-host` functionality,
    the system will display a file that matches `-NAME` before the
    `.txt` extension.  For example, if you have defined a target as 
    `oldunix@10.0.5.9:3333` the proxy will look for
    `block-oldunix.txt`, `deny-oldunix.txt`, and `issue-oldunix.txt`
    files to serve to the connecting users, before beginning their
    session (via TELNET to `10.0.5.9:3333`).  If a target-specific
    text files does not exist, then the standard file will be served
    (if existing).

* You need to start the proxy with `--whitelist` and/or `--blacklist`
  to enable the access control functionality.  If *only* the whitelist
  is enabled, **all** connections will be denied by default.  If
  *only* the whitelist is enabled, it will be impossible to exempt
  individual IP addresses when an entire range has been blocked, so it
  is recommended that you use with both lists, or the whitelist-only
  mode.

  * The format of the whitelist/blacklist is an IPv4 or IPv6 address
    (*e.g.,* `23.215.0.138`, `2600:1406:bc00:53::b81e:94ce`), or a
    CIDR block (*e.g.,* `123.45.0.0/17` which covers `123.45.0.0` to
    `123.45.127.255`, or `2600:1408:ec00:36::/64` covering
    `2600:1408:ec00:36:0000:0000:0000:0000` to
    `2600:1408:ec00:36:ffff:ffff:ffff:ffff`).  The whitelist always
    takes precedence over the blacklist.  If an address is allowed
    due to a whitelist match which would have otherwise been blocked
    by the blacklist, it is tagged as `EXEMPTED` in the logs.

* The `-v` or `--version` command shows detailed version information,
  including the versions of all embedded dependencies and the version
  of the Go compiler used to build the software:

```
DPS8M Proxy v0.0.0* (2025-Jul-17 ge3e61bc+) [linux/amd64]

+===========================+=========+
| Component                 | Version |
+===========================+=========+
| dps8m/proxy               | v0.0.0* |
| klauspost/compress        | v1.18.0 |
| spf13/pflag               | v1.0.6  |
| ulikunitz/xz              | v0.5.12 |
| golang.org/x/crypto       | v0.40.0 |
| kernel.org/.../libcap/cap | v1.2.76 |
| kernel.org/.../libcap/psx | v1.2.76 |
| Go compiler (gc)          | v1.24.5 |
+===========================+=========+
```

If you need to see even more details, use `go version -m proxy`.

### Port binding

* If you want to listen on the regular SSH port of 22 (without
  running as `root`, which is strongly discouraged), on Linux systems
  you can use `setcap` to allow the proxy to bind to low ports:

  ```sh
  sudo setcap 'cap_net_bind_service=+ep' "/path/to/proxy"
  ```

### Admin interaction

* The running proxy can be controlled with the following admin console
  commands:
  * `?` - Show help text
  * `c` - Show proxy configuration
  * `v` - Show version details
  * `l` - List active connections
  * `k` - Kill a connection
  * `d` - Deny new connections
  * `r` - Reload access control lists
  * `q` - Graceful shutdown
  * `Q` - Immediate shutdown (also via `^C`)
[]()

[]()

Most of these admin console commands are straightforward and should
be self-explanatory, although there are a few options that merit
further clarification:

* When the *Graceful shutdown* mode is active, any new connections are
  are denied (and are served an appropriate `deny.txt`).  Once all
  clients have disconnected, the proxy software will exit.  Note that
  new *monitoring sessions* can still connect to observe active users,
  as these sessions are automatically closed when their observation
  target disconnects.

* When the *Deny new connections* mode is active, any new connections
  are denied (and are served an appropriate `deny.txt`).  Also, any
  *logging* of new connections, including denied and rejected
  connections, is suppressed.  This can be useful if the admin console
  is overwhelmed with logging activity (such as during bot attacks,
  busy periods, or when troubleshooting).  Activating this mode can
  help reduce console noise, making it easier to perform admin actions
  such as viewing the configuration, or listing and killing active
  connections.

### Signals

* The proxy also acts on the following signals:
  * `SIGINT`, `SIGQUIT` - enables the *Immediate shutdown* mode
  * `SIGUSR1` - enables the *Graceful shutdown* mode
  * `SIGUSR2` - enables the *Deny new connections* mode
  * `SIGHUP` - reloads *access control lists*
    (`-whitelist`, `-blacklist`)

### User interaction

Users connected via SSH can send `^]` (*i.e.* `Control + ]`) during
a session to access the following following features from a menu:

* `A` sends an IAC `AYT` (*Are You There?*) to the remote host
* `B` sends an IAC `BREAK` signal to the remote host
* `K` toggles the transparent key remapping mode, which translates
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

This is a from-scratch re-implementation using
[Golang](https://go.dev/) of an older legacy program of the same name.
The original software used a multi-process architecture and consisted
of more than **10,000 SLOC** of haphazardly constructed code: ≅9,000
lines of [C-Kermit](https://www.kermitproject.org/) (*yes, the
[programming language](https://www.kermitproject.org/ckututor.html)*)
and [ksh93](https://github.com/ksh93/ksh), with small amounts of C
and Perl, which was difficult to maintain, configure, and securely
install.

This new implementation many lightweight *Goroutines* instead of
spawning multiple processes, resulting in significantly improved
performance and reduced system overhead.

It is also considerably simpler, per
[`scc`](https://github.com/boyter/scc):

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
		<th>3110</th>
		<th>537</th>
		<th>152</th>
		<th>2421</th>
		<th>0</th>
		<th>84931</th>
		<th>0</th>
	</tr><tr>
		<th>Plain Text</th>
		<th>4</th>
		<th>41</th>
		<th>5</th>
		<th>0</th>
		<th>36</th>
		<th>0</th>
		<th>2296</th>
		<th>0</th>
	</tr><tr>
		<th>YAML</th>
		<th>2</th>
		<th>39</th>
		<th>1</th>
		<th>5</th>
		<th>33</th>
		<th>0</th>
		<th>882</th>
		<th>0</th>
	</tr><tr>
		<th>Go Template</th>
		<th>1</th>
		<th>327</th>
		<th>64</th>
		<th>0</th>
		<th>263</th>
		<th>0</th>
		<th>13240</th>
		<th>0</th>
	</tr><tr>
		<th>License</th>
		<th>1</th>
		<th>22</th>
		<th>4</th>
		<th>0</th>
		<th>18</th>
		<th>0</th>
		<th>1121</th>
		<th>0</th>
	</tr><tr>
		<th>Makefile</th>
		<th>1</th>
		<th>204</th>
		<th>41</th>
		<th>47</th>
		<th>116</th>
		<th>0</th>
		<th>5957</th>
		<th>0</th>
	</tr><tr>
		<th>Markdown</th>
		<th>1</th>
		<th>370</th>
		<th>65</th>
		<th>0</th>
		<th>305</th>
		<th>0</th>
		<th>15777</th>
		<th>0</th>
	</tr><tr>
		<th>Shell</th>
		<th>1</th>
		<th>94</th>
		<th>24</th>
		<th>27</th>
		<th>43</th>
		<th>0</th>
		<th>2465</th>
		<th>0</th>
	</tr><tr>
		<th>TOML</th>
		<th>1</th>
		<th>15</th>
		<th>3</th>
		<th>3</th>
		<th>9</th>
		<th>0</th>
		<th>543</th>
		<th>0</th>
	</tr></tbody>
	<tfoot><tr>
		<th>Total</th>
		<th>19</th>
		<th>4222</th>
		<th>744</th>
		<th>234</th>
		<th>3244</th>
		<th>0</th>
		<th>127212</th>
		<th>0</th>
	</tr></tfoot></table>

## Future plans

1. Some features are still missing in this implementation and will be
   added in future updates.  Some of the features of the original
   legacy software that have not yet been re-implemented include
   *CAPTCHA*s, throttling, load-balancing, flow control, SSH targets,
   and TELNET listeners.

2. When users access an SSH listener, the connecting client may supply
   a password or present public keys for authentication.  These
   authentication attempts are currently recorded, but are not
   otherwise used by the proxy.  A future update may allow for public
   keys to be used for pre-authentication or to influence target
   routing.

## Compressed logs

By default, all session log files are compressed automatically when
the session terminates, and console log files are compressed when the
log rolls over (starting a new day).  When reviewing logs,
administrators often need to grep through all the past data, including
the compressed files. We recommend using
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

2. Convert the keys (using `ssh-keygen`) and rename them appropriately:

   ```sh
   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_rsa_key.tmp
   ssh-keygen -p -m PEM -N '' -P '' -f ssh_host_ed25519_key.tmp
   mv ssh_host_rsa_key.tmp ssh_host_rsa_key.pem
   mv ssh_host_ed25519_key.tmp ssh_host_ed25519_key.pem 
   ```
## Security

* The canonical home of this software is
  \<[**https://gitlab.com/dps8m/proxy**](https://gitlab.com/dps8m/proxy)\>.
* This software is intended to be **secure**.  If you find any
  security-related problems, please do not hesitate to
  [open an Issue](https://gitlab.com/dps8m/proxy/-/issues/new)
  or send an [e-mail](mailto:contact-project+dps8m-proxy-71601954-issue-@incoming.gitlab.com)
  to the author.

## License

* The `proxy` program is made available under the terms of the
  [MIT License](https://opensource.org/license/mit), with some bundled
  example and miscellaneous files distributed under the terms of the
  [MIT No Attribution License](https://opensource.org/license/mit-0).
