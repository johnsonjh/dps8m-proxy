##############################################################################
# DPS8M Proxy - Makefile
# Copyright (c) 2025-2026 Jeffrey H. Johnson
# Copyright (c) 2025-2026 The DPS8M Development Team
# SPDX-License-Identifier: MIT
# scspell-id: 5865f38c-6bd2-11f0-882d-80ee73e9b8e7
##############################################################################

##############################################################################
# Configuration

CGO_ENABLED=0
AWK?=$$(command -v goawk 2> /dev/null || command -v gawk 2> /dev/null || \
		command -v mawk 2> /dev/null || command -v awk)
CP=cp -f
GO=$$(command -v go)
GOTOOLCHAIN=auto
MV=mv -f
PERL=$$(command -v perl)
RM=rm -f
SED?=$$(command -v gsed 2> /dev/null || command -v sed)
SCCFLAGS=--exclude-file "LICENSE,REUSE.toml,README.md,renovate.json,\
		 .whitesource,.golangci.yml,dependabot.yml,.txt" \
		 --no-size --no-cocomo -ud --count-as 'tmpl:Markdown' \
		 --include-symlinks

##############################################################################
# Target: all

all: proxy

##############################################################################
# Target: proxy

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

clean:
	@env printf '%s\n' "🧹 Cleaning..." 2> /dev/null || :
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) clean -v
	$(RM) -r ./cross.bin/
	$(RM) ./README.md.sed
	$(RM) ./README.md.awk

##############################################################################
# Target: distclean

distclean: clean
	$(RM) ssh_host_ecdsa_key.pem ssh_host_ed25519_key.pem ssh_host_rsa_key.pem
	$(RM) ./tags ./GPATH ./GRTAGS ./GTAGS
	$(RM) -r ./log/
	test -d ./.git && $(RM) -r ./vendor/ || :

##############################################################################
# Target: tidy

tidy: go.mod
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) mod tidy -v

##############################################################################
# Target: test

test:
	@env printf '%s\n' "🧪 Running 'go test -v .'" 2> /dev/null || :
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) test -v .

##############################################################################
# Target: lint

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
		scspell \
		codespell \
		reuse \
		file-diff \
		revive \
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
# Target: file-diff

file-diff:
	diff LICENSE LICENSES/MIT.txt
	diff .gitlab/CODEOWNERS .github/CODEOWNERS

##############################################################################
# Target: golist

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

reuse:
	@command -v reuse > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ reuse not found" \
			2> /dev/null || :; exit 0; } ; \
		set -x; reuse lint -q || reuse lint

##############################################################################
# Target: gofmt

gofmt:
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) gofmt -d -e -s .

##############################################################################
# Target: goverify

goverify: go.mod
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) mod verify

##############################################################################
# Target: gotidydiff

gotidydiff: go.mod
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) mod tidy -diff

##############################################################################
# Target: golangci-lint

golangci-lint:
	@command -v golangci-lint > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ golangci-lint not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) golangci-lint run

##############################################################################
# Target: staticcheck

staticcheck:
	@command -v staticcheck > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ staticcheck not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) staticcheck .

##############################################################################
# Target: nilaway

nilaway:
	@command -v nilaway > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ nilaway not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) \
		nilaway \
			-experimental-anonymous-function \
			-experimental-struct-init \
			./...

##############################################################################
# Target: revive

revive:
	@command -v revive > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ revive not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) revive \
			-formatter stylish \
			-set_exit_status ./...

##############################################################################
# Target: errcheck

errcheck:
	@command -v errcheck > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ errcheck not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) errcheck

##############################################################################
# Target: deadcode

deadcode:
	@command -v deadcode > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ deadcode not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) deadcode ./...

##############################################################################
# Target: govulncheck

govulncheck:
	@command -v govulncheck > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ govulncheck not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) \
		govulncheck \
			-show color,traces \
			./...

##############################################################################
# Target: gopls

gopls:
	@command -v gopls > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ gopls not found!" \
			2> /dev/null || :; exit 0; } ; \
		$(RM) -r "${HOME:-/home}/.cache/goimports" > /dev/null 2>&1 || :; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) gopls check -severity=hint ./*.go

##############################################################################
# Target: gofumpt

gofumpt:
	@command -v gofumpt > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ gofumpt not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && printf '%s\n' \
		'GOSUMDB=sum.golang.org' || :) gofumpt -d -e .

##############################################################################
# Target: shfmt

shfmt: .cross.sh .cross-android.sh .lintsetup.sh .update-deps.sh
	@command -v shfmt > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ shfmt not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; shfmt -bn -sr -fn -i 2 -s -d \
			.cross.sh .cross-android.sh .lintsetup.sh .update-deps.sh

##############################################################################
# Target: shellcheck

shellcheck: .cross.sh .cross-android.sh .lintsetup.sh .update-deps.sh
	@command -v shellcheck > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ shellcheck not found!" \
			2> /dev/null || :; exit 0; } ; \
		set -x; shellcheck -s sh -o any,all \
			.cross.sh .cross-android.sh .lintsetup.sh .update-deps.sh

##############################################################################
# Target: codespell

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

govet:
	env GOTOOLCHAIN=$(GOTOOLCHAIN) $$($(GO) env 2>&1 | \
		grep -q "GOSUMDB=.*off.*" && \
		printf '%s\n' 'GOSUMDB=sum.golang.org' || :) $(GO) vet

##############################################################################
# Target: README.md

README.md doc docs: README.md.tmpl proxy
	@env printf '%s\n\n' "📚 Generating README.md..." 2> /dev/null || :
	@command -v perl > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ perl not found!" \
			2> /dev/null || :; exit 1; }
	@command -v scc > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ scc not found!" \
			2> /dev/null || :; exit 1; }
	$(CP) README.md.tmpl ./README.md
	@env printf '\n%s\n' "⚙️ Awk: Inserting version info..."  \
		2> /dev/null || :
	v="$$( ./proxy --version 2>&1 | $(AWK) \
	  'BEGIN { s = "" } \
	   { gsub(/\r/, ""); \
	     if (NR > 1) s = s ORS $$0; else s = $$0 } \
	   END { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$$/, "", s); \
	         print s }' )" ; \
	$(AWK) -v v="$$v" '{ gsub(/===VERSION===/, v); print }' README.md > README.md.awk && \
		$(MV) README.md.awk README.md
	grep -q '===VERSION===' ./README.md || exit 0
	@env printf '\n%s\n' "⚙️ Sed: Inserting help info..." \
		2> /dev/null || :
	h="$$( ./proxy --help 2>&1 | $(AWK) \
	  'BEGIN { s = "" } \
	   { gsub(/\r/, ""); \
	     if (NR > 1) s = s ORS $$0; else s = $$0 } \
	   END { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$$/, "", s); \
	         print s }' )" ; \
	$(AWK) -v h="$$h" '{ gsub(/===HELP===/, h); print }' README.md > README.md.awk && \
		$(MV) README.md.awk README.md
	grep -q '===HELP===' ./README.md || exit 0
	@env printf '\n%s\n' "⚙️ Awk: Inserting codepage list..." \
		2> /dev/null || :
	cp_list=$$( ./proxy --iconv help 2>&1 | $(AWK) '/^  "/ { match($$0, /"[^"]*"/); s = substr($$0, RSTART+1, RLENGTH-2); gsub(/"/,"`",s); printf "%s`\"%s\"`", sep, s; sep = ", "; } END { printf "." }' ); \
	$(AWK) -v cp="$$cp_list" '{ gsub(/===CODEPAGE===/, cp); print; }' ./README.md > ./README.md.awk && \
	$(MV) ./README.md.awk ./README.md
	grep -q '===CODEPAGE===' ./README.md || exit 0
	@env printf '\n%s\n' "🐪 Perl: Inserting scc output..." \
		2> /dev/null || :
	s="$$( scc $(SCCFLAGS) -f html-table 2>&1 | $(AWK) \
	  'BEGIN { s = "" } \
	   { gsub(/\r/, ""); \
	     if (NR > 1) s = s ORS $$0; else s = $$0 } \
	   END { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$$/, "", s); \
	         print s }' )" ; \
	$(AWK) -v s="$$s" '{ gsub(/===SCC===/, s); print }' README.md > README.md.awk && \
		$(MV) README.md.awk README.md
	grep -q '===SCC===' ./README.md || exit 0
	@env printf '\n%s\n' "⚙️ Sed: Redacting paths..." \
		2> /dev/null || :
	$(SED) \
	-e "s/$$(printf '\t')//g" \
	-e 's|^Usage for .*/proxy:|Usage for proxy:|' \
	< ./README.md > ./README.md.sed && \
		$(MV) ./README.md.sed ./README.md
	@env printf '\n%s\n\n' "📗 README.md generation successful." \
		2> /dev/null || :

##############################################################################
# Target: scc

scc:
	@command -v scc > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ scc not found!" \
			2> /dev/null || :; exit 1; } ; \
		set -x; scc $(SCCFLAGS)

##############################################################################
# Target: cross

cross: .cross.sh
	@env printf '\n%s\n\n' \
		"🛫 Starting cross-compilation (errors are non-fatal!)" \
			2> /dev/null || :
	@./.cross.sh
	@env printf '\n%s\n\n' \
		"🛬 Back from cross-compilation" 2> /dev/null || :

##############################################################################
# Target: scspell

scspell: ./.scspell/basedict.txt ./.scspell/dictionary.txt
	@command -v scspell > /dev/null 2>&1 || \
		{ env printf '%s\n' "⚠️ scspell not found!" \
			2> /dev/null || :; exit 1; }
	@env printf '%s\n' \
		"ℹ️ Running scspell, use scspell-fix to run interactively" \
			2> /dev/null || :
	$(RM) ./tags ./GPATH ./GRTAGS ./GTAGS
	scspell \
		--report-only \
		--override-dictionary ./.scspell/dictionary.txt \
		--base-dict ./.scspell/basedict.txt \
		$$( find . \( -path ./.git -o -path ./.venv -o -name '.doc.tmpl' \
			-o -name 'README.md' \) -prune -o -type f -exec \
			grep -l 'scspell-id:' {} \; )

##############################################################################
# Target: scspell-fix

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

strip sstrip:
	@env printf '%s\n' "📥 Stripping proxy binary..." 2> /dev/null || :
	@test -x "proxy" || \
		{ env printf '%s\n' "🚫 'proxy' not found, try running '$(MAKE)'" \
			2> /dev/null || :; \
		  exit 1; }
	@[ "$(uname -o 2> /dev/null)" = "illumos" ] || \
		{ set -x; env OBJECT_MODE=32_64 strip proxy \
		    2> /dev/null || :; }
	@command -v sstrip > /dev/null 2>&1 && \
		{ set -x; sstrip -z proxy \
		    2> /dev/null || :; }

##############################################################################
# Target: install-strip

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

.NOTPARALLEL:

##############################################################################

.PHONY: all proxy clean distclean tidy test lint check file-diff golist \
	reuse gofmt goverify gotidydiff golangci-lint staticcheck nilaway \
	revive errcheck deadcode govulncheck gopls gofumpt shfmt shellcheck \
	codespell tags ctags gtags GRPATH GRTAGS GTAGS govet doc docs scc \
	cross scspell scspell-fix strip sstrip install-strip install

##############################################################################
# Local Variables:
# mode: make
# tab-width: 4
# End:
##############################################################################
# vim: set ft=make noexpandtab tabstop=4 cc=78 :
##############################################################################
