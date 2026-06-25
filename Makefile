# Developer glue for lpf. Product commands and feature logic stay in OCaml.

DUNE ?= dune
OPAM ?= opam
LPF ?= $(DUNE) exec -- lpf
MAN_DIR ?= man/generated
PREFIX ?= /usr/local
POLICY ?= fixtures/policies/basic.lpf
OBSERVED ?= fixtures/nftables/basic.nft
REMOTE ?= remote-linux
REMOTE_DIR ?= /tmp/lpf-remote-check

.PHONY: all help deps build test check ci clean install uninstall
.PHONY: man-generate man-check man-install
.PHONY: policy-check policy-fmt policy-fmt-check fixture-check
.PHONY: plan rules-show rules-diff remote-check
.PHONY: release-checksums release-sign release-verify
.PHONY: static
.PHONY: deb rpm

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
	@printf '%s\n' '  make remote-check      run build/test/man-check on REMOTE=<ssh-host>'

deps:
	$(OPAM) install . --deps-only --with-test

build:
	$(DUNE) build

static:
	$(DUNE) build --profile=static bin/main.exe

# eBPF datapath object (Linux + clang/llvm + kernel BTF required).
bpf:
	sh bpf/build.sh

# Basic in-kernel datapath conformance matrix (root + bpftool required; Linux only).
bpf-e2e: bpf
	rm -rf /sys/fs/bpf/lpftest && mkdir -p /sys/fs/bpf/lpftest/prog
	bpftool prog loadall bpf/lpf_kern.o /sys/fs/bpf/lpftest/prog pinmaps /sys/fs/bpf/lpftest
	python3 bpf/e2e_progrun.py; status=$$?; rm -rf /sys/fs/bpf/lpftest; exit $$status

# Comprehensive 4-layer E2E runner (root + bpftool + python3 required).
# Control layers: LPF_EBPF_LAYERS=0,1,2,3 (default: all)
bpf-e2e-comprehensive: bpf
	rm -rf /sys/fs/bpf/lpftest && mkdir -p /sys/fs/bpf/lpftest/prog
	bpftool prog loadall bpf/lpf_kern.o /sys/fs/bpf/lpftest/prog pinmaps /sys/fs/bpf/lpftest
	python3 bpf/e2e_runner.py --layers $${LPF_EBPF_LAYERS:-0,1,2,3} --skip-build; status=$$?; rm -rf /sys/fs/bpf/lpftest; exit $$status

# Full Vagabond eBPF E2E suite (all layers including live Firecracker traffic).
bpf-e2e-vagabond:
	ci/vagabond/ebpf-e2e-suite.sh

# eBPF conntrack-specific E2E run.
bpf-e2e-ct: bpf
	ci/vagabond/ebpf-conntrack-suite.sh

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

# Release infrastructure
RELEASE_VERSION ?= $(shell $(LPF) version)
RELEASE_TARBALL ?= lpf-$(RELEASE_VERSION).tar.gz
CHECKSUM_FILE ?= SHA256SUMS
SIGN_KEY ?=

release-checksum:
	git archive --prefix=lpf-$(RELEASE_VERSION)/ -o $(RELEASE_TARBALL) HEAD
	sha256sum $(RELEASE_TARBALL) > $(CHECKSUM_FILE)
	@printf 'checksums written to %s\n' $(CHECKSUM_FILE)

release-sign: release-checksum
	@if [ -z "$(SIGN_KEY)" ]; then printf 'set SIGN_KEY to your GPG key ID\n'; exit 1; fi
	gpg --detach-sign --armor --local-user $(SIGN_KEY) $(CHECKSUM_FILE)
	gpg --detach-sign --armor --local-user $(SIGN_KEY) $(RELEASE_TARBALL)
	@printf 'signed %s and %s with key %s\n' $(RELEASE_TARBALL) $(CHECKSUM_FILE) $(SIGN_KEY)

release-verify:
	sha256sum -c $(CHECKSUM_FILE)
	@if [ -f $(CHECKSUM_FILE).asc ]; then gpg --verify $(CHECKSUM_FILE).asc; fi
	@if [ -f $(RELEASE_TARBALL).asc ]; then gpg --verify $(RELEASE_TARBALL).asc; fi
	@printf 'release verified\n'

deb:
	set -eu; rm -rf debian; cp -a packaging/deb debian; trap 'rm -rf debian' EXIT; dpkg-buildpackage -b -us -uc -d

rpm:
	set -eu; VERSION=$$($(LPF) version); RPM_TOPDIR="$$(pwd)/../lpf-rpmbuild"; OPAMSWITCH="$$(opam switch show)"; export OPAMSWITCH; rm -rf "$$RPM_TOPDIR"; mkdir -p "$$RPM_TOPDIR/BUILD" "$$RPM_TOPDIR/BUILDROOT" "$$RPM_TOPDIR/RPMS" "$$RPM_TOPDIR/SOURCES" "$$RPM_TOPDIR/SPECS" "$$RPM_TOPDIR/SRPMS"; git archive --prefix="lpf-$$VERSION/" -o "$$RPM_TOPDIR/SOURCES/lpf-$$VERSION.tar.gz" HEAD; rpmbuild -bb --nodeps packaging/rpm/lpf.spec --define "_topdir $$RPM_TOPDIR"
