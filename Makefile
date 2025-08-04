##############################################################################
# DPS8M Proxy - Makefile
# Copyright (c) 2025 Jeffrey H. Johnson
# Copyright (c) 2025 The DPS8M Development Team
# SPDX-License-Identifier: MIT
# scspell-id: 5865f38c-6bd2-11f0-882d-80ee73e9b8e7
##############################################################################

##############################################################################
# Configuration

SHELL=/bin/sh
CP=cp -f
PERL=perl
RM=rm -f
SED?=sed
SCCFLAGS=--exclude-file "LICENSE,REUSE.toml,README.md,renovate.json,\
		 .whitesource,.golangci.yml,dependabot.yml,.txt"            \
		 --no-size --no-cocomo -ud --count-as 'tmpl:Markdown'       \
		 --include-symlinks
.NOTPARALLEL:

##############################################################################
# Target: all

.PHONY: all
all: proxy

##############################################################################
# Target: proxy

.PHONY: proxy
proxy: tags
	@printf '%s\n' "🧩 Building proxy..."
	@env GOTOOLCHAIN=auto CGO_ENABLED=0 go build -trimpath -v && \
	test -x proxy 2> /dev/null && { \
		printf '%s\n\n' "✅ Build successful!"; \
		./proxy --version; exit 0; } || { \
		printf '\n%s\n\n' "💔 Build failed!"; exit 1; }

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
	$(RM) ssh_host_ecdsa_key.pem ssh_host_ed25519_key.pem ssh_host_rsa_key.pem
	$(RM) ./tags ./GPATH ./GRTAGS ./GTAGS
	$(RM) -r ./log/

##############################################################################
# Target: test

.PHONY: test
test:
	@printf '%s\n' "🧪 Running 'go test -v .'"
	env GOTOOLCHAIN=auto go test -v .

##############################################################################
# Target: lint

.PHONY: lint check
lint check:
	@printf '%s\n' "🧩 Running 'make clean'..."
	$(MAKE) clean
	@printf '\n%s\n' "🧩 Running 'make doc'..."
	$(MAKE) doc
	@printf '\n%s\n' "🧩 Running 'make test'..."
	$(MAKE) test
	@printf '\n%s\n' "🧩 Running 'make clean'..."
	$(MAKE) clean
	@printf '\n%s\n' "⚙️ Running linters..."
	$(MAKE) \
		codespell \
		scspell \
		revive \
		reuse \
		gofmt \
		gofumpt \
		govet \
		goverify \
		gotidydiff \
		staticcheck \
		errcheck \
		shellcheck \
		shfmt \
		golangci-lint \
		glab-lint \
		golist \
		govulncheck
	@test -z "$${CI_NO_CROSS:-}" && { \
		printf '\n%s\n' "🧩 Running 'make cross'..."; \
		set -x; env MAX_CPU=1 $(MAKE) cross; exit $${?}; } || true
	$(MAKE) clean
	@printf '\n%s\n\n' "🥇 Linting complete; carefully review the output."

##############################################################################
# Target: golist

.PHONY: golist
golist:
	@printf '\n%s\n' \
		"ℹ️ Finding any outdated dependencies... (may take a few moments)"
	@go list -u -f \
		'{{if (and (not (or .Main .Indirect)) .Update)}}{{.Path}}: {{.Version}} → {{.Update.Version}}{{end}}' \
		-m all

##############################################################################
# Target: glab-lint

.PHONY: glab-lint
glab-lint:
	@command -v glab > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ glab not found"; exit 0; } ; \
		set -x; glab ci lint || true

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
# Target: govulncheck

.PHONY: govulncheck
govulncheck:
	@command -v govulncheck > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ govulncheck not found!"; exit 0; } ; \
		set -x; govulncheck ./...

##############################################################################
# Target: gofumpt

.PHONY: gofumpt
gofumpt:
	@command -v gofumpt > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ gofumpt not found!"; exit 0; } ; \
		set -x; gofumpt -d -e .

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
		  gotags -f tags -R . > /dev/null 2>&1 || :; } || :
	@test -f ./tags || { \
		command -v ctags > /dev/null 2>&1 && \
			{ printf '%s\n' "🏷️ Building ctags database..."; \
			  ctags -R . > /dev/null 2>&1 || :; } || :; } || :
	@command -v gogtags > /dev/null 2>&1 && \
		{ printf '%s\n' "🏷️ Building gogtags database..."; \
		gogtags > /dev/null 2>&1 || :; } || :

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
	'BEGIN { ($$v=qx(./proxy --version))=~s/^\s+|\s+$$//g; $$v=~s/\r//g; } \
	s!===VERSION===!$$v!g' README.md
	grep -q '===VERSION===' README.md || exit 0
	@printf '\n%s\n' "🐪 Perl: Inserting help info..."
	$(PERL) -i -pe \
	'BEGIN { ($$v=qx(./proxy --help))=~s/^\s+|\s+$$//g; $$v=~s/\r//g; } \
	s!===HELP===!$$v!g' README.md
	grep -q '===HELP===' README.md || exit 0
	@printf '\n%s\n' "🐪 Perl: Inserting scc output..."
	$(PERL) -i -pe \
	'BEGIN { ($$v=qx(scc $(SCCFLAGS) -f html-table))=~s/^\s+|\s+$$//g; $$v=~s/\r//g; } \
	s!===SCC===!$$v!g' README.md
	grep -q '===SCC===' README.md || exit 0
	$(SED) -i "s/$$(printf '\t')//g" README.md
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
# Target: scspell

.PHONY: scspell
scspell: ./.scspell/basedict.txt ./.scspell/dictionary.txt
	@command -v scspell > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ scspell not found!"; exit 1; }
	@printf '%s\n' \
		"ℹ️ Running scspell, use scspell-fix target to run interactively"
	scspell \
		--report-only \
		--override-dictionary ./.scspell/dictionary.txt \
		--base-dict ./.scspell/basedict.txt \
		$$( find . \( -path ./.git -o -path ./.venv -o -name '.doc.tmpl' \
			-o -name 'README.md' \) -prune -o -type f -exec \
			grep -l 'scspell-id:' {} \; )

##############################################################################
# Target: scspell-fix

.PHONY: scspell-fix
scspell-fix: ./.scspell/basedict.txt ./.scspell/dictionary.txt
	@command -v scspell > /dev/null 2>&1 || \
		{ printf '%s\n' "⚠️ scspell not found!"; exit 1; }
	@printf '%s\n' \
		"ℹ️ Running scspell-fix, use scspell target to run non-interactively"
	scspell \
		--override-dictionary ./.scspell/dictionary.txt \
		--base-dict ./.scspell/basedict.txt \
		$$( find . \( -path ./.git -o -path ./.venv -o -name '.doc.tmpl' \
			-o -name 'README.md' \) -prune -o -type f -exec \
			grep -l 'scspell-id:' {} \; )

##############################################################################
# Target: strip

.PHONY: strip
strip:
	@printf '%s\n' "📥 Stripping proxy binary..."
	@test -x "proxy" || \
		{ printf '%s\n' "🚫 'proxy' not found, try running '$(MAKE)'"; \
		  exit 1; }
	env OBJECT_MODE=32_64 strip proxy

##############################################################################
# Target: install-strip

.PHONY: install-strip
install-strip:
	$(MAKE) strip
	$(MAKE) install

##############################################################################
# Target: install

DEST_NAME=dps8m-proxy
DEST_CONF=dps8m-proxy.conf
DEST_UNIT=dps8m-proxy.service

PREFIX?=/usr/local
FNLDIR=$(DESTDIR)$(PREFIX)
BINDIR=$(FNLDIR)/bin
ETCDIR=$(FNLDIR)/etc
UNTDIR=$(FNLDIR)/lib/systemd/system

INSTALL?=install
INSTALL_BIN=$(INSTALL) -m 0755
INSTALL_UNT=$(INSTALL) -m 0644

SETCAP?=$$(command -v setcap || true)
SETCAP_FLAGS='cap_net_bind_service+ep'

.PHONY: install
install:
	@printf '%s\n' "📥 Starting proxy installation..."
	@test -x "proxy" || \
		{ printf '%s\n' "🚫 'proxy' not found, try running '$(MAKE)'"; \
		  exit 1; }
	@printf '\n%s\n' "🔧 Check installation directories, create if missing..."
	mkdir -p \
		"$(BINDIR)" \
		"$(ETCDIR)" \
		"$(UNTDIR)"
	@printf '\n%s\n' "🔧 Backing up '$(DEST_NAME)' if possible..."
	test -f "$(BINDIR)"/$(DEST_NAME) && { \
		cp -fp "$(BINDIR)"/"$(DEST_NAME)" "$(BINDIR)"/"$(DEST_NAME).old"; \
		rm -f "$(BINDIR)"/"$(DEST_NAME)"; } || :
	@printf '\n%s\n' "🔧 Touching '$(DEST_CONF)' if missing..."
	test -f "$(ETCDIR)"/"$(DEST_CONF)" || \
		{ touch "$(ETCDIR)"/"$(DEST_CONF)"; } || :
	@printf '\n%s\n' "🔧 Installing new '$(DEST_NAME)'"
	$(INSTALL_BIN) "proxy" "$(BINDIR)"/"$(DEST_NAME)"
	@printf '\n%s\n' "🔧 Try to granting CAP_NET_BIND_SERVICE to $(DEST_NAME)"
	$(SETCAP) $(SETCAP_FLAGS) \
		"$(BINDIR)"/"$(DEST_NAME)" > /dev/null 2>&1 || :
	@printf '\n%s\n' "🔧 Installing new '$(DEST_UNIT)'"
	$(INSTALL_UNT) "systemd/dps8m-proxy.service" \
		"$(UNTDIR)"/"$(DEST_UNIT)"
	test -z "$(DESTDIR)" && { systemctl daemon-reload || :; } || :
	@printf '\n%s\n' "✅ Installation successful..."

##############################################################################
# vim: set ft=make noexpandtab tabstop=4 cc=78 :
##############################################################################
