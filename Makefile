##############################################################################
# Copyright (c) 2025 Jeffrey H. Johnson
# SPDX-License-Identifier: MIT
# vim ft=make expandtab tabstop=4 cc=78 :

##############################################################################
# Configuration

SHELL=/bin/sh
RM=rm -f

##############################################################################
# Target: all

.PHONY: all
all: proxy

##############################################################################
# Target: proxy

proxy: main.go
	go build -v

##############################################################################
# Target: clean

.PHONY: clean
clean:
	go clean -v

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
gofmt: main.go
	gofmt -d -e -s main.go

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
gofumpt: main.go
	@$$(command -v gofumpt > /dev/null 2>&1) || \
		{ printf '%s\n' "⚠️ gofumpt not found!"; exit 0; } ; \
		set -x; gofumpt -d -e -s main.go

##############################################################################
# Target: govet

.PHONY: govet
govet: main.go
	go vet

##############################################################################
