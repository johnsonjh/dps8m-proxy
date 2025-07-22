##############################################################################
# DPS8M Proxy - Makefile
# Copyright (c) 2025 Jeffrey H. Johnson
# Copyright (c) 2025 The DPS8M Development Team
# SPDX-License-Identifier: MIT

##############################################################################
# Configuration

SHELL=/bin/sh
CP=cp -f
PERL=perl
RM=rm -f
SCCFLAGS=--exclude-file "LICENSE,REUSE.toml,README.md,renovate.json,\
		 .whitesource,.golangci.yml,dependabot.yml,.txt"            \
		 --no-size --no-cocomo -ud --count-as 'tmpl:Markdown'       \
		 --include-symlinks
.NOTPARALLEL:

##############################################################################
# Target: all

.PHONY: all
all: tags proxy

##############################################################################
# Target: proxy

.PHONY: proxy
proxy:
	@printf '%s\n' "🧩 Building proxy..."
	@env GOTOOLCHAIN=auto CGO_ENABLED=0 go build -trimpath -v && \
	test -x proxy 2> /dev/null && { \
		printf '\n%s\n\n' "✅ Build successful:"; \
		./proxy --version 2> /dev/null; exit 0; } || { \
		printf '\n%s\n\n' "💔 Build failed!"; exit 1; }

##############################################################################
# Target: debug

.PHONY: debug
debug: tags
	@printf '%s\n' "🐛 Setting flags for debug build..."
	@env GOFLAGS="-tags=debug" $(MAKE) proxy

##############################################################################
# Target: clean

.PHONY: clean
clean:
	@printf '%s\n' "🧹 Cleaning..."
	env GOTOOLCHAIN=auto go clean -v
	$(RM) -r ./cross.bin/

##############################################################################
# Target: tidy

.PHONY: tidy
tidy: go.mod
	env GOTOOLCHAIN=auto go mod tidy -v

##############################################################################
# Target: distclean

.PHONY: distclean
distclean: clean
	$(RM) ssh_host_ed25519_key.pem ssh_host_rsa_key.pem
	$(RM) ./tags ./GPATH ./GRTAGS ./GTAGS
	$(RM) -r ./log/

##############################################################################
# Target: lint

.PHONY: lint check
lint check:
	@printf '%s\n' "🧩 Running 'make clean'..."
	$(MAKE) clean
	@printf '\n%s\n' "🧩 Running 'make doc'..."
	$(MAKE) doc
	@printf '\n%s\n' "🧩 Running 'make clean'..."
	$(MAKE) clean
	@printf '\n%s\n' "⚙️ Running linters..."
	$(MAKE) revive reuse gofumpt gofmt goverify gotidydiff govet staticcheck \
		errcheck shellcheck shfmt codespell golangci-lint
	@printf '\n%s\n' "🧩 Running 'make cross'..."
	$(MAKE) cross
	@printf '\n%s\n' "🧩 Running 'make clean'..."
	$(MAKE) clean
	@printf '\n%s\n\n' "🥇 Linting complete; carefully review the output."

##############################################################################
# Target: reuse

.PHONY: reuse
reuse:
	@command -v reuse > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ reuse not found"; exit 0; } ; \
		set -x; reuse lint -q || reuse lint

##############################################################################
# Target: gofmt

.PHONY: gofmt
gofmt:
	gofmt -d -e -s .

##############################################################################
# Target: goverify

.PHONY: goverify
goverify: go.mod
	env GOTOOLCHAIN=auto go mod verify

##############################################################################
# Target: gotidydiff

.PHONY: gotidydiff
gotidydiff: go.mod
	env GOTOOLCHAIN=auto go mod tidy -diff

##############################################################################
# Target: golangci-lint

.PHONY: golangci-lint
golangci-lint:
	@command -v golangci-lint > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ golangci-lint not found!"; exit 0; } ; \
		set -x; golangci-lint run

##############################################################################
# Target: staticcheck

.PHONY: staticcheck
staticcheck:
	@command -v staticcheck > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ staticcheck not found!"; exit 0; } ; \
		set -x; staticcheck .

##############################################################################
# Target: revive

.PHONY: revive
revive:
	@command -v revive > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ revive not found!"; exit 0; } ; \
		set -x; revive ./...

##############################################################################
# Target: errcheck

.PHONY: errcheck
errcheck:
	@command -v errcheck > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ errcheck not found!"; exit 0; } ; \
		set -x; errcheck

##############################################################################
# Target: gofumpt

.PHONY: gofumpt
gofumpt:
	@command -v gofumpt > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ gofumpt not found!"; exit 0; } ; \
		set -x; gofumpt -d -e -s .

##############################################################################
# Target: shfmt

.PHONY: shfmt
shfmt: .cross.sh
	@command -v shfmt > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ shfmt not found!"; exit 0; } ; \
		set -x; shfmt -bn -sr -fn -i 2 -s -d .cross.sh

##############################################################################
# Target: shellcheck

.PHONY: shellcheck
shellcheck: .cross.sh
	@command -v shellcheck > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ shellcheck not found!"; exit 0; } ; \
		set -x; shellcheck -s sh -o any,all .cross.sh

##############################################################################
# Target: codespell

.PHONY: codespell
codespell:
	@command -v codespell > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ codespell not found!"; exit 0; } ; \
		set -x; codespell .

##############################################################################
# Target: tags

# gotags https://github.com/jstemmer/gotags
# ctags: https://ctags.io/
# gogtags: https://github.com/juntaki/gogtags

.PHONY: tags ctags gtags GRPATH GRTAGS GTAGS
tags ctags gtags GRPATH GRTAGS GTAGS:
	@$(RM) ./tags > /dev/null 2>&1
	@command -v gotags > /dev/null 2>&1 && \
		{ printf '%s\n' "🏷️ Building gotags database..."; \
		  gotags -f tags -R . > /dev/null 2>&1 || true; } || true
	@test -f ./tags || { \
		command -v ctags > /dev/null 2>&1 && \
			{ printf '%s\n' "🏷️ Building ctags database..."; \
			  ctags -R . > /dev/null 2>&1 || true; } || true; } || true
	@command -v gogtags > /dev/null 2>&1 && \
		{ printf '%s\n' "🏷️ Building gogtags database..."; \
		gogtags > /dev/null 2>&1 || true; } || true

##############################################################################
# Target: govet

.PHONY: govet
govet:
	env GOTOOLCHAIN=auto go vet

##############################################################################
# Target: README.md

.PHONY: doc docs
README.md doc docs: README.md.tmpl proxy
	@printf '%s\n\n' "📚 Generating README.md..."
	@command -v perl > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ perl not found!"; exit 1; }
	@command -v scc > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ scc not found!"; exit 1; }
	$(CP) README.md.tmpl README.md
	@printf '\n%s\n' "🐪 Perl: Inserting version info..."
	$(PERL) -i -pe \
	'BEGIN { ($$v=qx(./proxy -v 2>&1))=~s/^\s+|\s+$$//g; $$v=~s/\r//g; } \
	s!===VERSION===!$$v!g' README.md
	grep -q '===VERSION===' README.md || exit 0
	@printf '\n%s\n' "🐪 Perl: Inserting help info..."
	$(PERL) -i -pe \
	'BEGIN { ($$v=qx(./proxy -h 2>&1 | grep -v "pflag: help requested"))=~s/^\s+|\s+$$//g; $$v=~s/\r//g; } \
	s!===HELP===!$$v!g' README.md
	grep -q '===HELP===' README.md || exit 0
	@printf '\n%s\n' "🐪 Perl: Inserting scc output..."
	$(PERL) -i -pe \
	'BEGIN { ($$v=qx(scc $(SCCFLAGS) -f html-table))=~s/^\s+|\s+$$//g; $$v=~s/\r//g; } \
	s!===SCC===!$$v!g' README.md
	grep -q '===SCC===' README.md || exit 0
	@printf '\n%s\n\n' "📗 README.md generation successful."

##############################################################################
# Target: scc

.PHONY: scc
scc:
	@command -v scc > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ scc not found!"; exit 1; } ; \
		set -x; scc $(SCCFLAGS)

##############################################################################
# Target: cross

.PHONY: cross
cross: .cross.sh
	@printf '\n%s\n\n' "🛫 Starting cross-compilation (errors are non-fatal!)"
	@./.cross.sh
	@printf '\n%s\n\n' "🛬 Back from cross-compilation"

##############################################################################
# vim: set ft=make noexpandtab tabstop=4 cc=78 :
##############################################################################
