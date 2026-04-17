<!-- Copyright (c) 2025-2026 Jeffrey H. Johnson -->
<!-- Copyright (c) 2025-2026 The DPS8M Development Team -->
<!-- SPDX-License-Identifier: MIT-0 -->
<!-- scspell-id: 82d273a4-3902-11f1-a5f6-80ee73e9b8e7 -->

# v1.1.1

* TBD

# v1.1.0

* New Features & Improvements
  * Updated command-line flag descriptions for `--compress-level` and
    `--log-dir-perm` to be more concise and consistent.
  * Transposed the example octal permissions for `--log-dir-perm`
    from "`755`, `750`" to "`750`, `755`" to align with the default
    value of `750`.
  * Standardized error messages for `--console-log`, `--compress-algo`,
    and `--compress-level` by changing "Invalid" to "Illegal" for
    better consistency.

# v1.0.59

* Documentation Updates
  * Fix incorrect Emacs key remapping table PgUp/PgDn details.
[]()

[]()
* Build System Improvements
  * Updated the `clean` make target in the `Makefile` to suppress
    unnecessary error output and improve the robustness of the cleanup
    process.

# v1.0.58

* Build System & Tooling Improvements
  * Significantly improved `Makefile` clarity by reorganizing variables
    and reducing long lines.
  * Moved Go template for dependency version checking to `GOLIST_TMPL`
    variable to improve maintainability.
  * Added a fallback mechanism to the `clean` make target in
    the `Makefile` to try using `-mod=readonly` if the default
    `go clean` operation fails.
[]()

[]()
* Dependency Management
  * Reorganized `go.mod` to explicitly separate direct, indirect,
    and test dependencies.
[]()

[]()
* CI/CD Updates
  * Optimized the GitLab CI/CD pipeline by removing the unnecessary
    installation of Perl.

# v1.0.57

* Build System & Tooling Improvements
  * Replaced Perl scripts with Awk scripts for documentation rebuilds.
[]()

[]()
* Installation & Usage Documentation Updates
  * Added detailed documentation for system-wide installations using
    `make install` and `make install-strip`, including information
    on `PREFIX` and `DESTDIR` environment variables.
  * Improved the `go install` documentation to recommend using
    `env GOTOOLCHAIN=auto` for a more robust installation experience.
  * Refined the explanation of how TELNET target-specific banner files
    are served when using the `--alt-host` functionality.
[]()

[]()
* Markdown and Formatting
  * Normalized punctuation, spacing, and Markdown formatting throughout
    the documentation to improve consistency and readability.
  * Added explicit code blocks for installation examples to better
    guide users.

# v1.0.56

* Build System Improvements
  * Enhanced the documentation generation process to automatically
    include the actual list of supported character maps for the
    `--iconv` flag.
  * Improved Awk detection in the `Makefile`.
  * Improved the `clean` make target in the `Makefile` to remove new
    temporary documentation build artifacts.
  * Updated `.gitignore` to exclude new temporary documentation
    build files.
[]()

[]()
* Documentation Improvements
  * Refined the visual layout of the documentation by categorizing
    the `--iconv` option details into clear bullet points.
  * Improved clarity in the description of the `--no-filter` option,
    emphasizing its requirement for ZMODEM and other `NULL`-terminated
    packet protocols.

# v1.0.55

* CLI & Usage Refinements
  * Updated the description for the `--no-banner` flag to be more
    explicit ("Disable the user SSH connection banner").
  * Improved the documentation for whitelist and blacklist file formats
    to clarify that they should contain "one item per line."
[]()

[]()
* Build System Improvements
  * Enhanced the documentation generation process in the `Makefile`
    to automatically redact the full local path of the binary from
    the generated help text.
[]()

[]()
* Testing Improvements
  * Refined the implementation of `TestNaturalLess` in `main_test.go`
    for better formatting and readability.

# v1.0.54

* Dependency Updates
  * Updated [`x/tools`](https://golang.org/x/tools)
    from v0.43.0 to v0.44.0.

# v1.0.53

* Dependency Updates
  * Updated [`x/crypto`](https://golang.org/x/crypto)
    from v0.49.0 to v0.50.0.
  * Updated [`x/term`](https://golang.org/x/term)
    from v0.41.0 to v0.42.0.
  * Updated [`x/text`](https://golang.org/x/text)
    from v0.35.0 to v0.36.0.
  * Updated [`x/mod`](https://golang.org/x/mod)
    from v0.34.0 to v0.35.0.
  * Updated [`x/net`](https://golang.org/x/net)
    from v0.52.0 to v0.53.0.

# v1.0.52

* Dependency Updates
  * Updated [`x/sys`](https://golang.org/x/sys)
    from v0.42.0 to v0.43.0.

# v1.0.51

* New Features & Improvements
  * Natural Sort Ordering: Implemented a new natural sort algorithm
    for ordering character map lists and TELNET target routes,
    ensuring that strings containing numbers are sorted logically
    (e.g., "ISO 8859-2" comes before "ISO 8859-10").
  * Enhanced Character Map Matching: Significantly improved the
    `--iconv` character map name matching logic. It now supports more
    flexible input by normalizing case, spaces, dashes, underscores,
    and common abbreviations like "CP" for "Code Page," "Win" for
    "Windows," and "Mac" for "Macintosh."
[]()

[]()
* Dependency Updates
  * Updated the
    [Go compiler and libraries](https://go.dev/doc/devel/release)
    from v1.26.1 to v1.26.2.
  * Updated
    [`libcap/cap`](https://kernel.org/pub/linux/libs/security/libcap/cap)
    from from v1.2.77 to v1.2.78.
  * Updated
    [`libcap/psx`](https://kernel.org/pub/linux/libs/security/libcap/psx)
    from from v1.2.77 to v1.2.78.
[]()

[]()
* Testing Improvements
  * Added test cases for the new natural sort algorithm, including
    scenarios for mixed alphanumeric strings and standard character
    map names.
  * Expanded tests for character map lookup to verify the improved
    normalization and fuzzy matching logic.

# v1.0.50

* Documentation Improvements
  * Added detailed descriptions for the `--iconv` option, explaining
    its use for character map conversion of TELNET text to UTF-8.
  * Added documentation for the new `--no-filter` option, which
    disables the stripping of `NULL` characters.
  * Updated the user control menu documentation to include the new `C`
    command, which toggles character set conversion during a session.

# v1.0.49

* New Features & Improvements
  * New CLI Option `--no-menu`: Added a new command-line flag to
    disable the SSH `Control-]` user menu, allowing for more
    restricted session configurations.
  * New CLI Option `--iconv`: Added a new command-line flag to
    enable conversion of legacy character maps to UTF-8.
[]()

[]()
* Interactive Menu Enhancements
  * Added the `C` command to the user control menu to allow users to
    toggle character map conversion (if enabled via `--iconv`)
    during a session.
  * Added status reporting for character map conversion to
    the `S` (Show Status) menu option.
  * Fixed bugs in the output alignment of the user control menu and
    improved connection statistics output.
[]()

[]()
* CI/CD Updates
  * Updated the Android build pipeline to use Android NDK r30-beta1.
[]()

[]()
* Testing Improvements
  * Added `TestFindCharmap` to verify the character map name
    normalization and fuzzy lookup logic.
  * Improved unit test parallelization and linting compatibility
    across several test functions.

# v1.0.48

* New Features & Improvements
  * New CLI Option `--no-filter`: Added a new command-line flag to
    disable the automatic stripping of `NULL` characters from the
    TELNET data stream.
[]()

[]()
* Code Quality & Maintenance
  * Updated linting suppressions to align with the latest
    `golangci-lint` rules.

# v1.0.47

* Dependency Updates
  * Updated
    [`klauspost/compress`](https://github.com/klauspost/compress)
    from v1.18.4 to v1.18.5.

# v1.0.46

* Dependency Updates
  * Updated [`x/tools`](https://golang.org/x/tools)
    from v0.42.0 to v0.43.0.

# v1.0.45

* Dependency Updates
  * Updated [`x/net`](https://golang.org/x/net)
    from v0.51.0 to v0.52.0.

# v1.0.44

* Dependency Updates
  * Updated [`x/crypto`](https://golang.org/x/crypto)
    from v0.48.0 to v0.49.0.
  * Updated [`x/term`](https://golang.org/x/term)
    from v0.40.0 to v0.41.0.
  * Updated [`x/mod`](https://golang.org/x/mod)
    from v0.33.0 to v0.34.0.

# v1.0.43

* Dependency Updates
  * Updated [`x/sys`](https://golang.org/x/sys)
    from v0.41.0 to v0.42.0.
  * Updated [`x/sync`](https://golang.org/x/sync)
    from v0.19.0 to v0.20.0.

# v1.0.42

* Dependency Updates
  * Updated the
    [Go compiler and libraries](https://go.dev/doc/devel/release)
    from v1.26.0 to v1.26.1.

# v1.0.41

* Dependency Updates
  * Updated [`spf13/pflag`](https://github.com/spf13/pflag)
    from v1.0.11-0.20260110151513-b85eb9e15911 to
    v1.0.11-0.20260305102058-3d32e71abc0b.

# v1.0.40

* New Features & Improvements
  * Added missing newline in `main.go` for better code readability.
  * Improved linter compliance between multiple versions by adding
    `nolintlint` to various `nolint` directives.
  * Refined timeout logic in `main.go` for better precision.

# v1.0.39

* New Features & Improvements
  * Migrated inline `gosec` exceptions to standard `golangci-lint`
    syntax in `utf8.go`.
[]()

[]()
* Dependency Updates
  * Updated [`x/net`](https://golang.org/x/net)
    from v0.50.0 to v0.51.0.

# v1.0.38

* New Features & Improvements
  * Added `--idle-def-max` and `--time-def-max` flags to set
    a connection timeout applied only for the default TELNET target.
  * Improved configuration display to show both global and
    default-only timeouts.
  * Added validation to ensure effective idle timeouts are not
    greater than or equal to total connection timeouts.
  * Improved linter compliance between multiple versions by
    adding `nolintlint` to various `nolint` directives.

# v1.0.37

* Dependency Updates
  * Updated the
    [Go compiler and libraries](https://go.dev/doc/devel/release)
    from v1.25.7 to v1.26.0.
  * Updated
    [`klauspost/compress`](https://github.com/klauspost/compress)
    from v1.18.3 to v1.18.4.
  * Updated [`x/crypto`](https://golang.org/x/crypto)
    from v0.47.0 to v0.48.0.
  * Updated [`x/mod`](https://golang.org/x/mod)
    from v0.32.0 to v0.33.0.
  * Updated [`x/net`](https://golang.org/x/net)
    from v0.49.0 to v0.50.0.
  * Updated [`x/sys`](https://golang.org/x/sys)
    from v0.40.0 to v0.41.0.
  * Updated [`x/term`](https://golang.org/x/term)
    from v0.39.0 to v0.40.0.
  * Updated [`x/tools`](https://golang.org/x/tools)
    from v0.41.0 to v0.42.0.

# v1.0.36

* Dependency Updates
  * Updated the
    [Go compiler and libraries](https://go.dev/doc/devel/release)
    from v1.25.6 to v1.25.7.
  * Updated [`miekg/dns`](https://github.com/miekg/dns)
    from v1.1.70 to v1.1.72.
[]()

[]()
* Build System Improvements
  * Updated `.golangci.yml` configuration.
  * Added `nolint:unqueryvet` directives to database bucket access in
    `database_common.go` to satisfy newer `golangci-lint` versions.

# v1.0.35

* Dependency Updates
  * Updated
    [`klauspost/compress`](https://github.com/klauspost/compress)
    from v1.18.2 to v1.18.3.

# v1.0.34

* Dependency Updates
  * Updated the
    [Go compiler and libraries](https://go.dev/doc/devel/release)
    from v1.25.5 to v1.25.6.

# v1.0.33

* Dependency Updates
  * Updated [`x/tools`](https://golang.org/x/tools)
    from v0.40.0 to v0.41.0.

# v1.0.32

* Dependency Updates
  * Updated [`x/crypto`](https://golang.org/x/crypto)
    from v0.46.0 to v0.47.0.
  * Updated [`x/net`](https://golang.org/x/net)
    from v0.48.0 to v0.49.0.

# v1.0.31

* Dependency Updates
  * Updated [`spf13/pflag`](https://github.com/spf13/pflag)
    from v1.0.11-0.20251007101450-6fcfbc9910e1 to
    v1.0.11-0.20260110151513-b85eb9e15911.
[]()

[]()
* Build System Improvements
  * Updated `Makefile` to clear the `goimports` cache before
    running `gopls` linting checks, avoiding a possible warning.

# v1.0.30

* Dependency Updates
  * Updated [`miekg/dns`](https://github.com/miekg/dns)
    from v1.1.69 to v1.1.70.
  * Updated [`x/mod`](https://golang.org/x/mod)
    from v0.31.0 to v0.32.0.
  * Updated [`x/term`](https://golang.org/x/term)
    from v0.38.0 to v0.39.0.

# v1.0.29

* Code Improvements
  * Normalized code style by adding missing whitespace in `main.go`.
[]()

[]()
* Dependency Updates
  * Updated [`google/gops`](https://github.com/google/gops)
    from v0.3.29-0.20250514124927-a2d8f7790eac to the final
    v0.3.29 release.
  * Updated [`x/sys`](https://golang.org/x/sys)
    from v0.39.0 to v0.40.0.

# v1.0.28

* New Features & Improvements
  * Improved performance and memory efficiency by pre-allocating data
    buffers in the TELNET negotiation logic.
[]()

[]()
* Build System Improvements
  * Updated `.update-deps.sh` to optimize dependency update order.
  * Updated `.gitignore` to exclude additional temporary and
    output files.

# v1.0.27

* CI/CD Updates
  * Improved packaging and archiving of source code in the CI pipeline.

# v1.0.26

* Documentation Updates
  * Regenerated project documentation only.

# v1.0.25

* Build System Improvements
  * Updated scripts to resect `GOPROXY` from the user environment.
  * Updated scripts to use the `DIRECT` variable to control Go
    proxy use, and no longer prioritizing direct module downloads.
  * Added `sstrip` an alias for `strip` make target in the `Makefile`.
  * Fixed a bug on illumos for the `strip` make target by not stripping
    the program using the illumos `strip` tool (due to a known bug that
    corrupts Go binaries).
  * Updated the `strip` make target to use the `sstrip` tool
    if available.
  * Updated the `Makefile` to only cleanup a `vendor` directory when
    using the `distclean` make target, and only when the `.git`
    directory exists.
  * Updated `.gitignore` to include core files and the
    `vendor` directory.
[]()

[]()
* CI/CD Updates
  * Deactivated the Python `venv` after linting and fixed `tar`
    path exclusions.
  * Added new `proxy.src.tar.gz` source archive (vendoring
    all modules) to GitLab Pages deployment.
  * Ensured proper `GOPROXY` variable is set in the
    GitLab CI/CD environment.

# v1.0.24

* New Features & Improvements
  * Fixed crash on 32-bit ARM devices (caused by atomic alignment
    issues) by reordering struct fields.

# v1.0.23

* New Features & Improvements
  * Updated version trimming logic to use `strings.Cut()`.

# v1.0.22

* Dependency Updates
  * Updated [`miekg/dns`](https://github.com/miekg/dns)
    from v1.1.68 to v1.1.69.
  * Updated [`uber/goleak`](https://go.uber.org/goleak)
    from v1.3.1-0.20241121203838-4ff5fa6529ee to
    v1.3.1-0.20251210191316-2b7fd8a0d244.

# v1.0.21

* Dependency Updates
  * Updated [`x/tools`](https://golang.org/x/tools)
    from v0.39.0 to v0.40.0.

# v1.0.20

* Dependency Updates
  * Updated [`x/net`](https://golang.org/x/net)
    from v0.47.0 to v0.48.0.

# v1.0.19

* New Features & Improvements
  * Improved robustness of SSH session handling by adding explicit
    checks for `nil` connections and contexts.
  * Improved safety of connection log generation routines when
    handling missing address information.

# v1.0.18

* Dependency Updates
  * Updated [`x/crypto`](https://golang.org/x/crypto)
    from v0.45.0 to v0.46.0.
  * Updated [`x/term`](https://golang.org/x/term)
    from v0.37.0 to v0.38.0.
  * Updated [`x/mod`](https://golang.org/x/mod)
    from v0.30.0 to v0.31.0.

# v1.0.17

* Dependency Updates
  * Updated [`x/sys`](https://golang.org/x/sys)
    from v0.38.0 to v0.39.0.
  * Updated [`x/sync`](https://golang.org/x/sync)
    from v0.18.0 to v0.19.0.

# v1.0.16

* Documentation Updates
  * Regenerated project documentation only.

# v1.0.15

* Dependency Updates
  * Updated the
    [Go compiler and libraries](https://go.dev/doc/devel/release)
    from v1.25.4 to v1.25.5.

# v1.0.14

* Dependency Updates
  * Updated
    [`klauspost/compress`](https://github.com/klauspost/compress)
    from v1.18.1 to v1.18.2.
[]()

[]()
* New Features & Improvements
  * Added `--keymap` option for enabling Emacs keymapping mode
    by default.
  * Applied minor formatting adjustments in `main.go`.

# v1.0.13

* New Features & Improvements
  * Refactored code by consolidating all version identification and
    printing functions to a dedicated file.
  * Removed unused IEC size constants from the `main` package.
[]()

[]()
* Build System Improvements
  * Added Emacs-style backup file patterns to the
    `.gitignore` configuration.
  * Included an Emacs local variables block in the
    documentation template.

# v1.0.12

* Dependency Updates
  * Updated [`arl/statsviz`](https://github.com/arl/statsviz)
    from v0.7.3 to v0.8.0.

# v1.0.11

* New Features & Improvements
  * Improved help output by clearly indicating the required argument
    types for all command-line flags.

# v1.0.10

* New Features & Improvements
  * Corrected the help text for the `--ssh-addr` argument by changing
    the text "strings" to just "string".
  * Improved the formatting of help output by adding missing spaces.
[]()

[]()
* Build System Improvements
  * Enabled the `color` and `trace` options of the `govulncheck`
    linting tool.

# v1.0.9

* Dependency Updates
  * Updated [`x/crypto`](https://golang.org/x/crypto)
    from v0.44.0 to v0.45.0.

# v1.0.8

* Dependency Updates
  * Updated [`arl/statsviz`](https://github.com/arl/statsviz)
    from v0.7.2 to v0.7.3.

# v1.0.7

* New Features & Improvements
  * Added support for detecting launches from FAR, Double Commander,
    and Total Commander on Microsoft Windows.
  * Normalized code style in the mDNS announcement logic.

# v1.0.6

* Dependency Updates
  * Updated [`x/tools`](https://golang.org/x/tools)
    from v0.38.0 to v0.39.0.

# v1.0.5

* New Features & Improvements
  * Prevented new SSH session requests if the session is
    already active.

# v1.0.4

* Build System Improvements
  * Added `proxy.exe` to the `.gitignore` file.
  * Improved the linting setup script support for Microsoft Windows
    including Cygwin support.
  * Updated the linting setup script to provide sane defaults
    for `GOPATH` and `GOEXE`.
  * Refactored variable names in the linting setup script
    for clarity.
  * Refined exported environment variables in the dependency
    update script.

# v1.0.3

* Dependency Updates
  * Updated [`x/crypto`](https://golang.org/x/crypto)
    from v0.43.0 to v0.44.0.
  * Updated [`x/net`](https://golang.org/x/net)
    from v0.46.0 to v0.47.0.

# v1.0.2

* New Features & Improvements
  * Refined code style in the version reporting functionality.
[]()

[]()
* Dependency Updates
  * Updated [`x/term`](https://golang.org/x/term)
    from v0.36.0 to v0.37.0.
  * Updated [`x/mod`](https://golang.org/x/mod)
    from v0.29.0 to v0.30.0.

# v1.0.1

* Build System Improvements
  * Added Emacs local variables configuration block to the `Makefile`.
  * Appeased linters for Microsoft Windows-specific code paths and
    improved the `trap_windows.go` error handling logic.
  * Implemented a workaround for an Apple Xcode-specific `make` bug
    affecting the `nilaway` and `revive` commands.
  * Appeased `gofumpt` by adjusting variable declaration
    in `trap_darwin.go`.
[]()

[]()
* Code Quality Improvements
  * Ensured `CloseHandle` is deferred with error suppression
    in `trap_windows.go`.
  * Added a `nil` check for `parentInfo` in `trap_darwin.go`.
  * Pre-allocated `commBytes` in `trap_darwin.go` to fix
    linter warnings.
  * Removed unnecessary byte conversions in `trap_darwin.go`.
  * Fixed a typo related to variable declarations in `trap_darwin.go`.
  * Refactored `unix.MAXCOMLEN` into constant `MAXCOMLEN`
    in `trap_darwin.go`.
  * Ensured consistent formatting of anonymous functions
    in `version.go`.

# v1.0.0

* Documentation Updates
  * Regenerated project documentation only.

# v0.1.69

* Dependency Updates
  * Updated [`x/sys`](https://golang.org/x/sys)
    from v0.37.0 to v0.38.0.
  * Updated [`x/sync`](https://golang.org/x/sync)
    from v0.17.0 to v0.18.0.

# v0.1.68

* CI/CD Updates
  * Added support for GitLab and GitHub `CODEOWNERS`.

# v0.1.67

* Build System Improvements
  * Added a lint check to verify that the top-level `LICENSE`
    file exactly matches `LICENSES/MIT.txt`.
[]()

[]()
* Documentation Updates
  * Updated the list of required development tools to include
    the POSIX.1 `diff` utility.

# v0.1.66

* CI/CD Updates
  * Updated the GitLab CI/CD configuration to call `pigz` with
    compression level 9 (instead of Zopfli).
[]()

[]()
* Build System Improvements
  * Modified the linter setup script to support the `VERBOSE`
    environment variable for controlling installation output.
  * Added the installation of `gotags` and `gogtags` tag generators
    to the linter setup script.
  * Enhanced the linter setup script to use the configured
    `GO` variable for all tool installations.

# v0.1.65

* New Features & Improvements
  * Switched to unsigned integers for certificate sizes
    and connection timeouts.
  * Added validation to ensure connection timeout values
    remain within safe ranges.
[]()

[]()
* Build System Improvements
  * Updated the `.gitignore` file to exclude more output files.

# v0.1.64

* Dependency Updates
  * Updated the
    [Go compiler and libraries](https://go.dev/doc/devel/release)
    from v1.25.3 to v1.25.4.

# v0.1.63

* New Features & Improvements
  * Added `--cert-rsa-bits` and `--cert-ecdsa-bits` command-line flags
    to allow users to specify key sizes for RSA and ECDSA host
    key generation.
  * Updated host key generation logging routines to include the sizes
    of the generated keys.

# v0.1.62

* Build System Improvements
  * Enabled symbol tables and DWARF information in pre-compiled
    release binaries by removing `-s` and `-w` linker flags.
[]()

[]()
* Testing Improvements
  * Integrated the upstream Google `deadcode` linter.
  * Added automated installation of `deadcode` linter in the lint
    setup script.
  * Added `deadcode` make target to the `Makefile` for manual
    and CI usage.

# v0.1.61

* New Features & Improvements
  * Implemented numerous defensive `nil`-checks for connection
    handling, mDNS listener addresses, and command-line arguments,
    as suggested by NilAway.
  * Added a `pflag_mustLookup` helper function to safely handle flag
    lookups while preventing potential `nil` pointer dereferences.
  * Normalized `fmt.Errorf` call formatting across the codebase for
    better consistency and readability.
[]()

[]()
* Testing Improvements
  * Integrated the NilAway static analysis tool into the linting suite
    for enhanced `nil`-safety verification.
  * Added the `wsl_v5` linter to the project and addressed identified
    style issues.
  * Adjusted `revive` linter configuration and addressed various
    linting findings.
  * Updated the lint setup script to automatically install and
    configure the new linters.

# v0.1.60

* New Features & Improvements
  * Enhanced error reporting across the database, host key generation,
    connection dialing, and logging modules (wrapping all returned
    errors with contextual information), as suggested by `wrapcheck`.
[]()

[]()
* Testing Improvements
  * Enabled the `depguard` linter in the static analysis configuration
    to restrict imports and explicitly deny usage of the deprecated
    `io/ioutil` package.
  * Enabled the `wrapcheck` linter to ensure all error returns from
    external packages are properly wrapped.

# v0.1.59

* New Features & Improvements
  * Updated error messages in the menu selection handler.
  * Optimized performance by replacing string formatting with direct
    string concatenation and formatting functions in logging
    and configuration display paths.
  * Added a missing newline in the Unix signal handling initialization
    for improved code readability.
[]()

[]()
* Testing Improvements
  * Enabled the `perfsprint` linter in the static analysis
    configuration and addressed all findings across the codebase.
  * Added `nolint` directives to suppress specific false positives in
    the UTF-8 handling logic.
[]()

[]()
* Build System Improvements
  * Adjusted the `GOPROXY` settings in the dependency update script.

# v0.1.58

* New Features & Improvements
  * Implemented new Linux-specific detection mechanisms to identify
    when the application is launched from native Linux
    GUI environments.
  * Added an explicit warning message to notify Linux users when the
    application is started from a file manager rather than a terminal.
  * Expanded the list of recognized Linux GUI launchers to include
    common desktop environments and file managers.
[]()

[]()
* CI/CD Updates
  * Updated the GitLab CI/CD configuration to use Zopfli compression
    via `pigz -11` for release assets.

# v0.1.57

* Build System Improvements
  * Simplified the Android cross-compilation script by removing
    redundant cleanup operations and stale code.
  * Updated the cross-compilation helper scripts to dynamically
    determine the Go toolchain version to use from the `go.mod` file.
  * Added the Android cross-compilation script to be checked by the
    `shfmt` and ShellCheck linters.
[]()

[]()
* Documentation Updates
  * Updated the `socat` integration example in the documentation to
    utilize UNIX domain sockets.
  * Added a hyperlink to the `socat` home page.

# v0.1.56

* CI/CD Updates
  * Optimized the GitLab CI/CD pipeline by caching the primary binary
    during cross-compilation to prevent redundant builds and avoid
    "dirty" version markers.

# v0.1.55

* CI/CD Updates
  * Rebuilt the proxy binary during the deployment process to ensure
    correct version information on the download web page.
  * Removed redundant debugging code from the pipeline configuration.

# v0.1.54

* CI/CD Updates
  * Corrected a bug preventing proper movement of Android build
    artifacts to the public directory in the GitLab CI/CD pipeline.

# v0.1.53

* CI/CD Updates
  * Added Alpine `bash` and `gcompat` packages to the
    GitLab CI/CD environment.
  * Updated the Android cross-compilation process in GitLab CI/CD
    to explicitly pass `pdpmake` in the `MAKE` environment variable.

# v0.1.52

* CI/CD Updates
  * Added a new Android cross-compilation job to the
    GitLab CI/CD pipeline.
  * Added `lzip`, `tar`, and the Android NDK to the GitLab CI/CD
    environment to facilitate Android CI builds.
[]()

[]()
* Build System Improvements
  * Added a new `.cross-android.sh` script to automate Android
    cross-compilation using the Android NDK.
  * Modified the `.cross.sh` script to exclude Android targets and
    refer users to the new `.cross-android.sh` script.
  * Updated the `Makefile` to be more POSIX-compliant and allowed
    overriding `GOTOOLCHAIN` and `CGO_ENABLED` variables.
[]()

[]()
* Testing Improvements
  * Enabled the `ireturn` linter in the static analysis configuration
    and addressed its findings.
[]()

[]()
* New Features & Improvements
  * Improved the console warning message for GUI launches on Linux to
    specifically mention not using a file manager.
  * Updated the `.gitignore` file to exclude
    Android-specific artifacts.

# v0.1.51

* New Features & Improvements
  * Implemented support for connecting to TELNET targets over UNIX
    domain sockets.
  * Added sanitization of non-ASCII characters from system error
    messages prior to transmitting them to connected clients, and
    a new `--no-sanitize` option to disable this new behavior.
  * Enhanced connection handling by ensuring all TCP connections
    utilize the `NoDelay` option.
  * Updated the console warning for GUI launches to appear after the
    help text for better visibility.
  * Standardized all spelling to American English conventions.
  * Improved connection termination logic by removing redundant
    mutex locking.
  * Enhanced error logging for failed TELNET target connections with
    better contextual information.
[]()

[]()
* Testing Improvements
  * Refactored code structure to satisfy the `noinlineerr` linter.
  * Applied `ireturn` linter compliance to key loading functions.
[]()

[]()
* Build System Improvements
  * Updated the dependency maintenance script to prioritize direct
    module downloads over the proxy.
  * Code cleanup for improved readability.

# v0.1.50

* Build System Improvements
  * Improved the console output messages for the `scspell`
    and `scspell-fix` make targets.

# v0.1.49

* New Features & Improvements
  * Added a new `--no-console` command-line argument to completely
    disable the interactive admin console.
[]()

[]()
* Build System Improvements
  * Improved build reliability on macOS by explicitly calling
    the external `printf` utility (known to properly handle
    Unicode output).

# v0.1.48

* New Features & Improvements
  * Applied various minor style and whitespace adjustments to enhance
    code consistency and readability.
[]()

[]()
* Dependency Updates
  * Updated
    [`libcap/cap`](https://kernel.org/pub/linux/libs/security/libcap/cap)
    from v1.2.76 to v1.2.77.
  * Updated
    [`libcap/psx`](https://kernel.org/pub/linux/libs/security/libcap/psx)
    from v1.2.76 to v1.2.77.

# v0.1.47

* Documentation Updates
  * Added information about source code tag generation using the
    `gogtags`, `gotags`, and `universal-ctags` tools to the
    project documentation.

# v0.1.46

* New Features & Improvements
  * Implemented detection for GUI-based launches on Windows, macOS,
    and Linux to prevent accidental execution outside of a terminal.
  * Added a prompt to wait for the Enter key to be pressed when a GUI
    launch is detected before exiting the application.
  * Refactored signal handling logic into platform-specific files
    for better maintainability.
  * Extended the `.gitignore` file to include IBM OS/400 specific
    build artifacts.
[]()

[]()
* Documentation Updates
  * Updated the help and usage information output to include the
    project home page and bug reporting URL.
[]()

[]()
* Dependency Updates
  * Promoted [`x/sys`](golang.org/x/sys) from an indirect to
    a direct dependency at version v0.37.0.

# v0.1.45

* New Features & Improvements
  * Improved grammatical clarity, corrected typographical errors, and
    added hyperlinks in the project documentation.

# v0.1.44

* New Features & Improvements
  * Corrected typographical and grammatical errors in
    the documentation.

# v0.1.43

* CI/CD Updates
  * Eliminated the `coreutils` package dependency by removing the
    use of the `stdbuf` command in the GitLab CI/CD configuration.

# v0.1.42

* CI/CD Updates
  * Added the `coreutils` package to the GitLab CI/CD Alpine build
    environment (to provide the `stdbuf` utility).
  * Utilized `stdbuf` to ensure line-buffered output for several
    build and test commands.
  * Corrected quoting for the `PATH` environment variable in
    the GitLab CI/CD configuration.
  * Removed redundant Go telemetry reconfiguration from the CI
    build scripts.

# v0.1.41

* CI/CD Updates
  * Updated GitLab CI/CD configuration to address various YAML
    style and syntax issues.

# v0.1.40

* CI/CD Updates
  * Updated GitLab CI configuration to use the colon shell builtin
    instead of `true` for command continuations.
  * Added the `!usr-merge-nag` Alpine meta-package to the
    GitLab CI/CD environment and ensured any error output is
    redirected to null.
[]()

[]()
* Build System Improvements
  * Simplified shell commands in the `systemd` service file by
    replacing `true` with the colon shell builtin.

# v0.1.39

* Documentation Updates
  * Regenerated project documentation only.

# v0.1.38

* CI/CD Updates
  * Updated the GitLab CI/CD configuration to use the linter setup
    script (instead of explicit installation commands).

# v0.1.37

* Documentation Updates
  * Added `gopls` to the list of required development tools.

# v0.1.36

* New Features & Improvements
  * Reformatted help output to maintain consistent indentation
    and style after updates to latest `pflag` dependency.
  * Improved version reporting of the `pflag` dependency to show more
    human-readable version information.
[]()

[]()
* Build System Improvements
  * Updated dependency update script to track the `pflag`
    master branch.
[]()

[]()
* Dependency Updates
  * Updated [`spf13/pflag`](https://github.com/spf13/pflag)
    from v1.0.10 to v1.0.11-0.20251007101450-6fcfbc9910e1.
[]()

[]()
* Internal Improvements
  * Adjusted code in `main.go` to satisfy new linter requirements for
    unchecked return values.

# v0.1.35

* Internal Improvements
  * Simplified function signatures and improved code
    formatting across the project via `gofumpt -s`.
  * Adjusted whitespace and comments to improve source
    code readability.

# v0.1.34

* Miscellaneous Improvements
  * Fixed a typo in the `systemd` service file comments.

# v0.1.33

* Build System Improvements
  * Integrated `gopls` and `govulncheck` into the linting process
    and added corresponding `Makefile` targets.
  * Updated the lint setup script to install
    `gopls` and `govulncheck`.
[]()

[]()
* Internal Improvements
  * Modernized conditional logic in IBM AIX-specific signal handling
    by utilizing the built-in `max` function.
  * Removed redundant `return` statements from multiple files to
    satisfy `gopls` checks.

# v0.1.32

* Dependency Updates
  * Updated
    [`klauspost/compress`](https://github.com/klauspost/compress)
    from v1.18.0 to v1.18.1.

# v0.1.31

* New Features & Improvements
  * Optimized string formatting operations by utilizing `fmt.Appendf`
    in place of `fmt.Sprintf` wrapped in byte slices.
  * Modernized conditional logic and data types by utilizing the
    built-in `max` function and the `any` type.
  * Updated the TELNET negotiation logic to identify and skip
    malformed sub-negotiation packets.

# v0.1.30

* Dependency Updates
  * Updated the
    [Go compiler and libraries](https://go.dev/doc/devel/release)
    from v1.25.2 to v1.25.3.

# v0.1.29

* Dependency Updates
  * Updated [`x/crypto`](https://golang.org/x/crypto)
    from v0.42.0 to v0.43.0.
  * Updated [`x/term`](https://golang.org/x/term)
    from v0.35.0 to v0.36.0.
  * Updated [`x/mod`](https://golang.org/x/mod)
    from v0.28.0 to v0.29.0.
  * Updated [`x/net`](https://golang.org/x/net)
    from v0.45.0 to v0.46.0.
  * Updated [`x/tools`](https://golang.org/x/tools)
    from v0.37.0 to v0.38.0.

# v0.1.28

* Dependency Updates
  * Updated [`x/sys`](https://golang.org/x/sys)
    from v0.36.0 to v0.37.0.

# v0.1.27

* Build System Improvements
  * Removed the (unnecessary) `SHELL` override from the `Makefile`.
[]()

[]()
* Dependency Updates
  * Updated the
    [Go compiler and libraries](https://go.dev/doc/devel/release)
    from v1.25.1 to v1.25.2.
  * Updated [`arl/statsviz`](https://github.com/arl/statsviz)
    from v0.7.1 to v0.7.2.
  * Updated [`x/net`](https://golang.org/x/net)
    from v0.44.0 to v0.45.0.

# v0.1.26

* Documentation Updates
  * Regenerated project documentation only.

# v0.1.25

* Internal Improvements
  * Enabled (and appeased) the `godoclint` linter.

# v0.1.24

* Build System Improvements
  * Added a new (MIT-0 licensed) lint setup script to automate
    the installation of Go-based linters and development tools.
  * Added a new script to facilitate automated dependency updates.
  * Added these scripts to be checked by the `shfmt` and
    ShellCheck linters.

# v0.1.23 to v0.1.2

* TBD

# v0.1.1

* Initial public release.

<!--
Local Variables:
mode: markdown
End:
-->
<!-- vim: set ft=markdown expandtab cc=72 : -->
<!-- EOF -->
