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
    from `755`, `750` to `750`, `755` to align with the default value
    of `750`.
  * Standardized error messages for `--console-log`, `--compress-algo`,
    and `--compress-level` by changing "Invalid" to "Illegal" for
    better consistency.

# v1.0.59

* Build System Improvements
  * Updated the `clean` target in the `Makefile` to suppress
    unnecessary error output and improve the robustness of the cleanup
    process.

# v1.0.58

* Build System & Tooling Improvements
  * Significantly improved `Makefile` clarity by reorganizing variables
    and reducing long lines.
  * Moved Go template for dependency version checking to `GOLIST_TMPL`
    variable to improve maintainability.
  * Added a fallback mechanism to the `clean` target in the `Makefile`
    to try `-mod=readonly` if the default `go clean` operation fails.
[]()

[]()
* Dependency Management
  * Reorganized `go.mod` to explicitly separate direct, indirect,
    and test dependencies.
[]()

[]()
* CI/CD Updates
  * Optimized the GitLab CI/CD pipelines by removing the unnecessary
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
  * Refined the explanation of how target-specific text files are
    served when using the `--alt-host` functionality.
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
  * Improved the `clean` target in the `Makefile` to remove new
    temporary documentation build artifacts.
  * Updated `.gitignore` to exclude new temporary documentation build
    files (`README.md.awk`).
[]()

[]()
* Documentation Improvements
  * Refined the visual layout of the documentation by categorizing
    the `--iconv` option details into clear bullet points.
  * Improved clarity in the description of the `--no-filter` option,
    emphasizing its requirement for ZMODEM and other NULL-terminated
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
  * Updated golang.org/x/tools from v0.43.0 to v0.44.0.

# v1.0.53

* Dependency Updates
  * Updated golang.org/x/crypto from v0.49.0 to v0.50.0.
  * Updated golang.org/x/term from v0.41.0 to v0.42.0.
  * Updated golang.org/x/text from v0.35.0 to v0.36.0.
  * Updated golang.org/x/mod from v0.34.0 to v0.35.0.
  * Updated golang.org/x/net from v0.52.0 to v0.53.0.

# v1.0.52

* Dependency Updates
  * Updated golang.org/x/sys from v0.42.0 to v0.43.0.

# v1.0.51

* New Features & Improvements
  * Natural Sort Ordering: Implemented a new natural sort algorithm for
    ordering character map lists and target routes, ensuring that
    strings containing numbers are sorted logically (e.g., "ISO 8859-2"
    comes before "ISO 8859-10").
  * Enhanced Character Map Matching: Significantly improved the
    `--iconv` character map name matching logic. It now supports more
    flexible input by normalizing case, spaces, dashes, underscores,
    and common abbreviations like "cp" for "codepage," "win" for
    "windows," and "mac" for "macintosh."
[]()

[]()
* Dependency Updates
  * Updated Go compiler from v1.26.1 to v1.26.2.
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
    disables the stripping of NULL characters.
  * Updated the user control menu documentation to include the new `C`
    command, which toggles character set conversion during a session.

# v1.0.49

* New Features & Improvements
  * New CLI Option `--no-menu`: Added a new command-line flag to
    disable the SSH "Control-]" user menu, allowing for more
    restricted session configurations.
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
    disable the automatic stripping of NULL characters from the TELNET
    data stream.
[]()

[]()
* Code Quality & Maintenance
  * Updated linting suppressions to align with the latest
    `golangci-lint` rules.

# v1.0.47

* Dependency Updates
  * Updated github.com/klauspost/compress from v1.18.4 to v1.18.5.

# v1.0.46

* Dependency Updates
  * Updated golang.org/x/tools from v0.42.0 to v0.43.0.

# v1.0.45

* Dependency Updates
  * Updated golang.org/x/net from v0.51.0 to v0.52.0.

# v1.0.44

* Dependency Updates
  * Updated golang.org/x/crypto from v0.48.0 to v0.49.0.
  * Updated golang.org/x/term from v0.40.0 to v0.41.0.
  * Updated golang.org/x/mod from v0.33.0 to v0.34.0.

# v1.0.43

* Dependency Updates
  * Updated golang.org/x/sys from v0.41.0 to v0.42.0.
  * Updated golang.org/x/sync from v0.19.0 to v0.20.0.

# v1.0.42

* Dependency Updates
  * Updated Go compiler from v1.26.0 to v1.26.1.

# v1.0.41

* Dependency Updates
  * Updated spf13/pflag from v1.0.11-0.20260110151513-b85eb9e15911
    to v1.0.11-0.20260305102058-3d32e71abc0b.

# v1.0.40

* New Features & Improvements
  * Added missing newline in `main.go` for better code readability.
  * Improved linter compliance between multiple versions by adding
    `nolintlint` to various `nolint` directives.
  * Refined timeout logic in `main.go` for better precision.

# v1.0.39

* New Features & Improvements
  * Migrated inline gosec exceptions to standard `golangci-lint`
    syntax in `utf8.go`.
[]()

[]()
* Dependency Updates
  * Updated golang.org/x/net from v0.50.0 to v0.51.0.

# v1.0.38

* New Features & Improvements
  * Added `--idle-def-max` and `--time-def-max` flags to set
    a connection timeout applied only to the default target.
  * Improved configuration display to show both global and
    default-target-only timeouts.
  * Added validation to ensure effective idle timeouts are not
    greater than or equal to total connection timeouts.
  * Improved linter compliance between multiple versions by
    adding `nolintlint` to various `nolint` directives.

# v1.0.37

* Dependency Updates
  * Updated Go compiler from v1.25.7 to v1.26.0.
  * Updated github.com/klauspost/compress from v1.18.3 to v1.18.4.
  * Updated golang.org/x/crypto from v0.47.0 to v0.48.0.
  * Updated golang.org/x/mod from v0.32.0 to v0.33.0.
  * Updated golang.org/x/net from v0.49.0 to v0.50.0.
  * Updated golang.org/x/sys from v0.40.0 to v0.41.0.
  * Updated golang.org/x/term from v0.39.0 to v0.40.0.
  * Updated golang.org/x/tools from v0.41.0 to v0.42.0.

# v1.0.36

* Dependency Updates
  * Updated Go compiler from v1.25.6 to v1.25.7.
  * Updated github.com/miekg/dns from v1.1.70 to v1.1.72.
[]()

[]()
* Build System Improvements
  * Updated `.golangci.yml` configuration.
  * Added `nolint:unqueryvet` directives to database bucket access in
    `database_common.go` to satisfy newer `golangci-lint` versions.

# v1.0.35

* Dependency Updates
  * Updated github.com/klauspost/compress from v1.18.2 to v1.18.3.

# v1.0.34

* Dependency Updates
  * Updated Go compiler from v1.25.5 to v1.25.6.

# v1.0.33

* Dependency Updates
  * Updated golang.org/x/tools from v0.40.0 to v0.41.0.

# v1.0.32

* Dependency Updates
  * Updated golang.org/x/crypto from v0.46.0 to v0.47.0.
  * Updated golang.org/x/net from v0.48.0 to v0.49.0.

# v1.0.31

* Dependency Updates
  * Updated spf13/pflag from v1.0.11-0.20251007101450-6fcfbc9910e1
    to v1.0.11-0.20260110151513-b85eb9e15911.
[]()

[]()
* Build System Improvements
  * Updated `Makefile` to clear the `goimports` cache before
    running `gopls` linting checks, avoiding a possible warning.

# v1.0.30

* Dependency Updates
  * Updated github.com/miekg/dns from v1.1.69 to v1.1.70.
  * Updated golang.org/x/mod from v0.31.0 to v0.32.0.
  * Updated golang.org/x/term from v0.38.0 to v0.39.0.

# v1.0.29

* Code Improvements
  * Normalized code style by adding missing whitespace in main.go.
[]()

[]()
* Dependency Updates
  * Updated github.com/google/gops from
    v0.3.29-0.20250514124927-a2d8f7790eac to the final v0.3.29 release.
  * Updated golang.org/x/sys from v0.39.0 to v0.40.0.

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
    proxy use.
  * Added `sstrip` an alias for `strip` target in the `Makefile`.
  * Fixed a bug on illumos for the `strip` make target by not stripping
    the program using the illumos `strip` tool (due to known bugs that
    corrupt Golang binaries).
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
  * Deactivated the Python venv after linting and fixed tar
    path exclusions.
  * Added new `proxy.src.tar.gz` source archive (vendoring
    all modules) to GitLab Pages deployment.
  * Ensured proper `GOPROXY` variable is set in GitLab CI environment.

# v1.0.24

* New Features & Improvements
  * Fixed crash on 32-bit ARM devices (caused by atomic alignment
    issues) by reordering struct fields.

# v1.0.23

* New Features & Improvements
  * Updated version trimming logic to use `strings.Cut()`.

# v1.0.22

* Dependency Updates
  * Updated github.com/miekg/dns from v1.1.68 to v1.1.69.
  * Updated go.uber.org/goleak from
    v1.3.1-0.20241121203838-4ff5fa6529ee to
    v1.3.1-0.20251210191316-2b7fd8a0d244.

# v1.0.21

* Dependency Updates
  * Updated golang.org/x/tools from v0.39.0 to v0.40.0.

# v1.0.20

* Dependency Updates
  * Updated golang.org/x/net from v0.47.0 to v0.48.0.

# v1.0.19

* New Features & Improvements
  * Improved robustness of SSH session handling by adding explicit
    checks for `nil` connections and contexts.
  * Improved safety of connection log generation when handling missing
    address information.

# v1.0.18

* Dependency Updates
  * Updated golang.org/x/crypto from v0.45.0 to v0.46.0.
  * Updated golang.org/x/term from v0.37.0 to v0.38.0.
  * Updated golang.org/x/mod from v0.30.0 to v0.31.0.

# v1.0.17

* Dependency Updates
  * Updated golang.org/x/sys from v0.38.0 to v0.39.0.
  * Updated golang.org/x/sync from v0.18.0 to v0.19.0.

# v1.0.16

* Documentation Updates
  * Regenerated project documentation only.

# v1.0.15

* Dependency Updates
  * Updated Go compiler from v1.25.4 to v1.25.5.

# v1.0.14

* Dependency Updates
  * Updated github.com/klauspost/compress from v1.18.1 to v1.18.2.
[]()

[]()
* New Features & Improvements
  * Added `--keymap` option for enabling Emacs keymapping mode
    by default.
  * Applied minor formatting adjustments in `main.go`.

# v1.0.13

* New Features & Improvements
  * Refactored code by moving all version identification and printing
    functions to a dedicated file.
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
  * Updated github.com/arl/statsviz from v0.7.3 to v0.8.0.

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
  * Updated golang.org/x/crypto from v0.44.0 to v0.45.0.

# v1.0.8

* Dependency Updates
  * Updated github.com/arl/statsviz from v0.7.2 to v0.7.3.

# v1.0.7

* New Features & Improvements
  * Added support for detecting launches from FAR, Double Commander,
    and Total Commander on Microsoft Windows.
  * Normalized code style in the mDNS announcement logic.

# v1.0.6

* Dependency Updates
  * Updated golang.org/x/tools from v0.38.0 to v0.39.0.

# v1.0.5

* New Features & Improvements
  * Prevented new SSH session requests if the session is
    already active.

# v1.0.4

* Build System Improvements
  * Added `proxy.exe` to the `.gitignore` file.
  * Improved the linting setup script support for Windows
    including Cygwin support.
  * Updated the linting setup script to provide sane defaults
    for `GOPATH` and `GOEXE`.
  * Refactored variable names in the linting setup script
    for clarity.
  * Refined exported environment variables in the dependency
    update script.

# v1.0.3

* Dependency Updates
  * Updated golang.org/x/crypto from v0.43.0 to v0.44.0.
  * Updated golang.org/x/net from v0.46.0 to v0.47.0.

# v1.0.2

* New Features & Improvements
  * Refined code style in the version reporting functionality.
[]()

[]()
* Dependency Updates
  * Updated golang.org/x/term from v0.36.0 to v0.37.0.
  * Updated golang.org/x/mod from v0.29.0 to v0.30.0.

# v1.0.1

* Build System Improvements
  * Added Emacs local variables configuration block to the `Makefile`.
  * Appeased linters for Windows-specific code paths and improved
    the `trap_windows.go` error handling logic.
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
  * Updated golang.org/x/sys from v0.37.0 to v0.38.0.
  * Updated golang.org/x/sync from v0.17.0 to v0.18.0.

# v0.1.68

* CI/CD Updates
  * Added support for GitLab and GitHub `CODEOWNERS`.

# v0.1.67 to v0.1.1

* TBD

<!--
Local Variables:
mode: markdown
End:
-->
<!-- vim: set ft=markdown expandtab cc=72 : -->
<!-- EOF -->
