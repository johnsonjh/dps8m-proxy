##############################################################################
# Copyright (c) 2025 Jeffrey H. Johnson
# Copyright (c) 2025 The DPS8M Development Team
# SPDX-License-Identifier: MIT

##############################################################################
# Configuration

SHELL=/bin/sh
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
	@env CGO_ENABLED=0 go build -trimpath -v
	@test -x proxy 2> /dev/null && \
		{ \
			printf '%s\n' "Build successful:"; \
			go version -m proxy 2> /dev/null | \
				grep -E "$$(printf '\t')(mod|dep)$$(printf '\t')" \
					2> /dev/null; \
		}

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

.PHONY: lint
lint: reuse gofumpt gofmt goverify gotidydiff govet

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
# Target: gofumpt

.PHONY: gofumpt
gofumpt:
	@$$(command -v gofumpt > /dev/null 2>&1) || \
		{ printf '%s\n' "⚠️ gofumpt not found!"; exit 0; } ; \
		set -x; gofumpt -d -e -s .

##############################################################################
# Target: govet

.PHONY: govet
govet:
	go vet

##############################################################################
# Target: cross

.PHONY: cross
cross:
	-@./.cross.sh

##############################################################################
# vim: set ft=make noexpandtab tabstop=4 cc=78 :
##############################################################################
