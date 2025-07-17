##############################################################################
# Copyright (c) 2025 Jeffrey H. Johnson
# Copyright (c) 2025 The DPS8M Development Team
# SPDX-License-Identifier: MIT

##############################################################################
# Configuration

SHELL=/bin/sh
CP=cp -f
PERL=perl
RM=rm -f
.NOTPARALLEL:

##############################################################################
# Target: all

.PHONY: all
all: proxy

##############################################################################
# Target: proxy

.PHONY: proxy
proxy:
	@env CGO_ENABLED=0 go build -trimpath -v && \
	test -x proxy 2> /dev/null && { \
		printf '\n%s\n\n' "✅ Build successful:"; \
		./proxy --version 2> /dev/null; } || \
	printf '\n%s\n\n' "💔 Build failed!"

##############################################################################
# Target: clean

.PHONY: clean
clean:
	go clean -v
	$(RM) -r ./cross.bin/

##############################################################################
# Target: tidy

.PHONY: tidy
tidy: go.mod
	go mod tidy -v

##############################################################################
# Target: distclean

.PHONY: distclean
distclean: clean
	$(RM) ssh_host_ed25519_key.pem ssh_host_rsa_key.pem
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
	@printf '\n%s\n' "🧩 Running linters..."
	$(MAKE) revive reuse gofumpt gofmt goverify gotidydiff govet staticcheck \
		errcheck shellcheck
	@printf '\n%s\n' "🧩 Running 'make cross'..."
	$(MAKE) cross
	@printf '\n%s\n' "🧩 Running 'make clean'..."
	$(MAKE) clean

##############################################################################
# Target: reuse

.PHONY: reuse
reuse:
	@$$(command -v reuse > /dev/null 2>&1) || \
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
	go mod verify

##############################################################################
# Target: gotidydiff

.PHONY: gotidydiff
gotidydiff: go.mod
	go mod tidy -diff

##############################################################################
# Target: staticcheck

.PHONY: staticcheck
staticcheck:
	@$$(command -v staticcheck > /dev/null 2>&1) || \
		{ printf '%s\n' "⚠️ staticcheck not found!"; exit 0; } ; \
		set -x; staticcheck .

##############################################################################
# Target: revive

.PHONY: revive
revive:
	@$$(command -v revive > /dev/null 2>&1) || \
		{ printf '%s\n' "⚠️ revive not found!"; exit 0; } ; \
		set -x; revive ./...

##############################################################################
# Target: errcheck

.PHONY: errcheck
errcheck:
	@$$(command -v errcheck > /dev/null 2>&1) || \
		{ printf '%s\n' "⚠️ errcheck not found!"; exit 0; } ; \
		set -x; errcheck

##############################################################################
# Target: gofumpt

.PHONY: gofumpt
gofumpt:
	@$$(command -v gofumpt > /dev/null 2>&1) || \
		{ printf '%s\n' "⚠️ gofumpt not found!"; exit 0; } ; \
		set -x; gofumpt -d -e -s .

##############################################################################
# Target: shellcheck

.PHONY: shellcheck
shellcheck: .cross.sh
	@$$(command -v shellcheck > /dev/null 2>&1) || \
		{ printf '%s\n' "⚠️ shellcheck not found!"; exit 0; } ; \
		set -x; shellcheck -o any,all .cross.sh

##############################################################################
# Target: govet

.PHONY: govet
govet:
	go vet

##############################################################################
# Target: README.md

.PHONY: doc
README.md doc: README.md.tmpl proxy
	@$$(command -v perl > /dev/null 2>&1) || \
		{ printf '%s\n' "⚠️ perl not found!"; exit 1; }
	$(CP) README.md.tmpl README.md
	$(PERL) -i -pe \
		'BEGIN {($$v=qx(./proxy -v 2>&1))=~s/^\s+|\s+$$//g;$$v=~s/\r//g;} \
		s!===VERSION===!$$v!g' README.md
	$(PERL) -i -pe \
		'BEGIN {($$v=qx(./proxy -h 2>&1))=~s/^\s+|\s+$$//g;$$v=~s/\r//g;} \
		s!===HELP===!$$v!g' README.md

##############################################################################
# Target: cross

.PHONY: cross
cross: .cross.sh
	-@./.cross.sh

##############################################################################
# vim: set ft=make noexpandtab tabstop=4 cc=78 :
##############################################################################
