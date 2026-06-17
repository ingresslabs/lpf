# Developer glue for lpf. Product commands and feature logic stay in OCaml.

DUNE ?= dune
OPAM ?= opam
LPF ?= $(DUNE) exec -- lpf
MAN_DIR ?= man/generated
PREFIX ?= /usr/local
POLICY ?= fixtures/policies/basic.lpf
OBSERVED ?= fixtures/nftables/basic.nft
REMOTE ?= hawking
REMOTE_DIR ?= /tmp/lpf-remote-check

.PHONY: all help deps build test check ci clean install uninstall
.PHONY: man-generate man-check man-install
.PHONY: policy-check policy-fmt policy-fmt-check fixture-check
.PHONY: plan rules-show rules-diff remote-check

all: build

help:
	@printf '%s\n' 'lpf make targets:'
	@printf '%s\n' '  make deps              install opam dependencies for build and tests'
	@printf '%s\n' '  make build             build the OCaml library and CLI'
	@printf '%s\n' '  make test              run the Dune test suite'
	@printf '%s\n' '  make check             build, test, check man pages, and smoke fixtures'
	@printf '%s\n' '  make clean             remove Dune build output'
	@printf '%s\n' '  make man-generate      regenerate man pages from OCaml metadata'
	@printf '%s\n' '  make man-check         verify generated man pages are current'
	@printf '%s\n' '  make man-install       install man pages under PREFIX=/usr/local'
	@printf '%s\n' '  make policy-check      run lpf check on POLICY=fixtures/policies/basic.lpf'
	@printf '%s\n' '  make policy-fmt        print formatted POLICY output'
	@printf '%s\n' '  make policy-fmt-check  verify POLICY is already formatted'
	@printf '%s\n' '  make fixture-check     run lpf check on non-invalid policy fixtures'
	@printf '%s\n' '  make plan              print JSON plan for POLICY'
	@printf '%s\n' '  make rules-show        render nftables rules for POLICY'
	@printf '%s\n' '  make rules-diff        diff OBSERVED ruleset against POLICY'
	@printf '%s\n' '  make remote-check      run build/test/man-check on REMOTE=hawking'

deps:
	$(OPAM) install . --deps-only --with-test

build:
	$(DUNE) build

test:
	$(DUNE) runtest

check: build test man-check fixture-check rules-diff

ci: check

clean:
	$(DUNE) clean

install:
	$(DUNE) build @install
	$(DUNE) install

uninstall:
	$(DUNE) uninstall

man-generate:
	$(LPF) man generate --dir $(MAN_DIR)

man-check:
	$(LPF) man check --dir $(MAN_DIR)

man-install:
	$(LPF) man install --prefix $(PREFIX)

policy-check:
	$(LPF) check $(POLICY)

policy-fmt:
	$(LPF) fmt $(POLICY)

policy-fmt-check:
	$(LPF) fmt --check $(POLICY)

fixture-check:
	@set -eu; \
	for policy in fixtures/policies/*.lpf; do \
		case "$$policy" in \
			*invalid*) continue ;; \
		esac; \
		printf 'checking %s\n' "$$policy"; \
		$(LPF) check "$$policy" >/dev/null; \
	done

plan:
	$(LPF) plan --json $(POLICY)

rules-show:
	$(LPF) rules show $(POLICY)

rules-diff:
	$(LPF) rules diff --observed $(OBSERVED) $(POLICY)

remote-check:
	git archive --format=tar HEAD | ssh $(REMOTE) 'set -eu; rm -rf "$(REMOTE_DIR)"; mkdir -p "$(REMOTE_DIR)"; tar -xf - -C "$(REMOTE_DIR)"; cd "$(REMOTE_DIR)"; dune build; dune runtest; dune exec -- lpf man check'
