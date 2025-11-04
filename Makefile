##############################################################################
# DPS8M Proxy - Makefile
# Copyright (c) 2025 Jeffrey H. Johnson
# Copyright (c) 2025 The DPS8M Development Team
# SPDX-License-Identifier: MIT
# scspell-id: 5865f38c-6bd2-11f0-882d-80ee73e9b8e7
##############################################################################

##############################################################################
# Configuration

CGO_ENABLED=0
CP=cp -f
GO=$$(command -v go 2> /dev/null || printf '%s\n' "go")
GOTOOLCHAIN=auto
PERL=perl
RM=rm -f
SED?=sed
SCCFLAGS=--exclude-file "LICENSE,REUSE.toml,README.md,renovate.json,\
		 .whitesource,.golangci.yml,dependabot.yml,.txt" \
		 --no-size --no-cocomo -ud --count-as 'tmpl:Markdown' \
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
	@env printf '%s\n' "🧩 Building proxy..." 2> /dev/null || :
	@env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) \
		CGO_ENABLED=$(CGO_ENABLED) $(GO) build -trimpath -v && \
	test -x proxy 2> /dev/null && { \
		env printf '%s\n\n' "✅ Build successful!" 2> /dev/null || :; \
		./proxy --version; exit 0; } || { \
		env printf '\n%s\n\n' "💔 Build failed!" 2> /dev/null || :; exit 1; }

##############################################################################
# Target: clean

.PHONY: clean
clean:
	@env printf '%s\n' "🧹 Cleaning..." 2> /dev/null || :
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) clean -v
	$(RM) -r ./cross.bin/

##############################################################################
# Target: tidy

.PHONY: tidy
tidy: go.mod
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) mod tidy -v

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
	@env printf '%s\n' "🧪 Running 'go test -v .'" 2> /dev/null || :
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) test -v .

##############################################################################
# Target: lint

.PHONY: lint check
lint check:
	@env printf '%s\n' "🧩 Running 'make clean'..." 2> /dev/null || :
	$(MAKE) clean
	@env printf '\n%s\n' "🧩 Running 'make doc'..." 2> /dev/null || :
	$(MAKE) doc
	git restore "README.md" > /dev/null 2>&1 || :
	@env printf '\n%s\n' "🧩 Running 'make test'..." 2> /dev/null || :
	$(MAKE) test
	@env printf '\n%s\n' "🧩 Running 'make clean'..." 2> /dev/null || :
	$(MAKE) clean
	@env printf '\n%s\n' "⚙️ Running linters..." 2> /dev/null || :
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
		deadcode \
		shellcheck \
		shfmt \
		golangci-lint \
		nilaway \
		golist \
		govulncheck \
		gopls
	@test -z "$${CI_NO_CROSS:-}" && { \
		env printf '\n%s\n' "🧩 Running 'make cross'..." 2> /dev/null || :; \
		set -x; env MAX_CPU=1 $(MAKE) cross; exit $${?}; } || :
	$(MAKE) clean
	@env printf '\n%s\n\n' \
		"🥇 Linting complete; carefully review the output." 2> /dev/null || :

##############################################################################
# Target: golist

.PHONY: golist
golist:
	@env printf '\n%s\n' \
		"ℹ️ Finding any outdated dependencies... (may take a few moments)" \
			 2> /dev/null || :
	@env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) list -u -f \
		'{{if (and (not (or .Main .Indirect)) .Update)}}{{.Path}}: {{.Version}} → {{.Update.Version}}{{end}}' \
		-m all

##############################################################################
# Target: reuse

.PHONY: reuse
reuse:
	@command -v reuse > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ reuse not found" \
			2> /dev/null || :; exit 0; } ; \
		set -x; reuse lint -q || reuse lint

##############################################################################
# Target: gofmt

.PHONY: gofmt
gofmt:
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
	grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
	'GOSUMDB=sum.golang.org' || :) gofmt -d -e -s .

##############################################################################
# Target: goverify

.PHONY: goverify
goverify: go.mod
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) mod verify

##############################################################################
# Target: gotidydiff

.PHONY: gotidydiff
gotidydiff: go.mod
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) mod tidy -diff

##############################################################################
# Target: golangci-lint

.PHONY: golangci-lint
golangci-lint:
	@command -v golangci-lint > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ golangci-lint not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) golangci-lint run

##############################################################################
# Target: staticcheck

.PHONY: staticcheck
staticcheck:
	@command -v staticcheck > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ staticcheck not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) staticcheck .

##############################################################################
# Target: nilaway

.PHONY: nilaway
nilaway:
	@command -v nilaway > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ nilaway not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) nilaway \
			-experimental-anonymous-function \
			-experimental-struct-init ./...

##############################################################################
# Target: revive

.PHONY: revive
revive:
	@command -v revive > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ revive not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) revive \
			-formatter stylish -set_exit_status ./...

##############################################################################
# Target: errcheck

.PHONY: errcheck
errcheck:
	@command -v errcheck > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ errcheck not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) errcheck

##############################################################################
# Target: deadcode

.PHONY: deadcode
deadcode:
	@command -v deadcode > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ deadcode not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) deadcode ./...

##############################################################################
# Target: govulncheck

.PHONY: govulncheck
govulncheck:
	@command -v govulncheck > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ govulncheck not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) govulncheck ./...

##############################################################################
# Target: gopls

.PHONY: gopls
gopls:
	@command -v gopls > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ gopls not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) gopls check -severity=hint ./*.go

##############################################################################
# Target: gofumpt

.PHONY: gofumpt
gofumpt:
	@command -v gofumpt > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ gofumpt not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) gofumpt -d -e .

##############################################################################
# Target: shfmt

.PHONY: shfmt
shfmt: .cross.sh .cross-android.sh .lintsetup.sh .update-deps.sh
	@command -v shfmt > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ shfmt not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; shfmt -bn -sr -fn -i 2 -s -d \
			.cross.sh .cross-android.sh .lintsetup.sh .update-deps.sh

##############################################################################
# Target: shellcheck

.PHONY: shellcheck
shellcheck: .cross.sh .cross-android.sh .lintsetup.sh .update-deps.sh
	@command -v shellcheck > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ shellcheck not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; shellcheck -s sh -o any,all \
			.cross.sh .cross-android.sh .lintsetup.sh .update-deps.sh

##############################################################################
# Target: codespell

.PHONY: codespell
codespell:
	@command -v codespell > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ codespell not found!" \
			2> /dev/null || :; exit 0; } ; \
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
		{ env printf '%s\n' "🏷️ Building gotags database..." \
			2> /dev/null || :; \
		  gotags -f tags -R . > /dev/null 2>&1 || :; } || :
	@test -f ./tags || { \
		command -v ctags > /dev/null 2>&1 && \
			{ env printf '%s\n' "🏷️ Building ctags database..." \
				2> /dev/null || :; \
			  ctags -R . > /dev/null 2>&1 || :; } || :; } || :
	@command -v gogtags > /dev/null 2>&1 && \
		{ env printf '%s\n' "🏷️ Building gogtags database..." \
			2> /dev/null || :; \
		gogtags > /dev/null 2>&1 || :; } || :

##############################################################################
# Target: govet

.PHONY: govet
govet:
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) vet

##############################################################################
# Target: README.md

.PHONY: doc docs
README.md doc docs: README.md.tmpl proxy
	@env printf '%s\n\n' "📚 Generating README.md..." 2> /dev/null || :
	@command -v perl > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ perl not found!" \
			2> /dev/null || :; exit 1; }
	@command -v scc > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ scc not found!" \
			2> /dev/null || :; exit 1; }
	$(CP) README.md.tmpl README.md
	@env printf '\n%s\n' "🐪 Perl: Inserting version info..." \
		2> /dev/null || :
	$(PERL) -i -pe \
	'BEGIN { ($$v=qx(./proxy --version))=~s/^\s+|\s+$$//g; $$v=~s/\r//g; } \
	s!===VERSION===!$$v!g' README.md
	grep -q '===VERSION===' README.md || exit 0
	@env printf '\n%s\n' "🐪 Perl: Inserting help info..." \
		2> /dev/null || :
	$(PERL) -i -pe \
	'BEGIN { ($$v=qx(./proxy --help))=~s/^\s+|\s+$$//g; $$v=~s/\r//g; } \
	s!===HELP===!$$v!g' README.md
	grep -q '===HELP===' README.md || exit 0
	@env printf '\n%s\n' "🐪 Perl: Inserting scc output..." \
		2> /dev/null || :
	$(PERL) -i -pe \
	'BEGIN { ($$v=qx(scc $(SCCFLAGS) -f html-table))=~s/^\s+|\s+$$//g; $$v=~s/\r//g; } \
	s!===SCC===!$$v!g' README.md
	grep -q '===SCC===' README.md || exit 0
	$(SED) -i "s/$$(printf '\t')//g" README.md
	@env printf '\n%s\n\n' "📗 README.md generation successful." \
		2> /dev/null || :

##############################################################################
# Target: scc

.PHONY: scc
scc:
	@command -v scc > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ scc not found!" \
			2> /dev/null || :; exit 1; } ; \
		set -x; scc $(SCCFLAGS)

##############################################################################
# Target: cross

.PHONY: cross
cross: .cross.sh
	@env printf '\n%s\n\n' \
		"🛫 Starting cross-compilation (errors are non-fatal!)" \
			2> /dev/null || :
	@./.cross.sh
	@env printf '\n%s\n\n' \
		"🛬 Back from cross-compilation" 2> /dev/null || :

##############################################################################
# Target: scspell

.PHONY: scspell
scspell: ./.scspell/basedict.txt ./.scspell/dictionary.txt
	@command -v scspell > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ scspell not found!" \
			2> /dev/null || :; exit 1; }
	@env printf '%s\n' \
		"ℹ️ Running scspell, use scspell-fix to run interactively" \
			2> /dev/null || :
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
		{ env printf '%s\n' "⚠️ scspell not found!" \
			2> /dev/null || :; exit 1; }
	@env printf '%s\n' \
		"ℹ️ Running scspell-fix, use scspell to run non-interactively" \
			2> /dev/null || :
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
	@env printf '%s\n' "📥 Stripping proxy binary..." 2> /dev/null || :
	@test -x "proxy" || \
		{ env printf '%s\n' "🚫 'proxy' not found, try running '$(MAKE)'" \
			2> /dev/null || :; \
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

SETCAP?=$$(command -v setcap || printf '%s\n' "true")
SETCAP_FLAGS='cap_net_bind_service+ep'

SYSTEMCTL=$$(command -v systemctl || printf '%s\n' "true")
SYSTEMCTL_FLAGS='daemon-reload'

.PHONY: install
install:
	@env printf '%s\n' "📥 Starting proxy installation..." 2> /dev/null || :
	@test -x "proxy" || \
		{ env printf '%s\n' "🚫 'proxy' not found, try running '$(MAKE)'" \
			2> /dev/null || :; \
		  exit 1; }
	@env printf '\n%s\n' \
		"🔧 Check installation directories, create if missing..." \
			2> /dev/null || :
	mkdir -p \
		"$(BINDIR)" \
		"$(ETCDIR)" \
		"$(UNTDIR)"
	@env printf '\n%s\n' \
		"🔧 Backing up '$(DEST_NAME)' if possible..." 2> /dev/null || :
	test -f "$(BINDIR)"/$(DEST_NAME) && { \
		cp -fp "$(BINDIR)"/"$(DEST_NAME)" "$(BINDIR)"/"$(DEST_NAME).old"; \
		rm -f "$(BINDIR)"/"$(DEST_NAME)"; } || :
	@env printf '\n%s\n' \
		"🔧 Touching '$(DEST_CONF)' if missing..." 2> /dev/null || :
	test -f "$(ETCDIR)"/"$(DEST_CONF)" || \
		{ touch "$(ETCDIR)"/"$(DEST_CONF)"; } || :
	@env printf '\n%s\n' "🔧 Installing new '$(DEST_NAME)'" \
		2> /dev/null || :
	$(INSTALL_BIN) "proxy" "$(BINDIR)"/"$(DEST_NAME)"
	@env printf '\n%s\n' \
		"🔧 Try granting CAP_NET_BIND_SERVICE to $(DEST_NAME)" \
			2> /dev/null || :
	test -f /.dockerenv || { $(SETCAP) $(SETCAP_FLAGS) \
		"$(BINDIR)"/"$(DEST_NAME)" > /dev/null 2>&1 || :; } || :
	@env printf '\n%s\n' \
		"🔧 Installing new '$(DEST_UNIT)'" 2> /dev/null || :
	$(INSTALL_UNT) "systemd/dps8m-proxy.service" \
		"$(UNTDIR)"/"$(DEST_UNIT)"
	test -z "$(DESTDIR)" && { $(SYSTEMCTL) $(SYSTEMCTL_FLAGS) || :; } || :
	@env printf '\n%s\n' "✅ Installation successful..." 2> /dev/null || :

##############################################################################
# vim: set ft=make noexpandtab tabstop=4 cc=78 :
##############################################################################
