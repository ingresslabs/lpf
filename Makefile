# Developer glue for lpf. Product commands and feature logic stay in OCaml.
#
# Quick reference:
#   make              build lpf
#   make test         run unit test suite
#   make ci           full CI check (build + test + fixtures + man pages)
#   make docker       build all 5 CI distro images
#   make packages     build RPM, DEB, binary, CNI packages via Docker
#   make ansible      run Ansible role validation
#   make bpf-e2e      eBPF E2E with live traffic (root required)

DUNE       ?= dune
OPAM       ?= opam
LPF        ?= $(DUNE) exec -- lpf
MAN_DIR    ?= man/generated
PREFIX     ?= /usr/local
POLICY     ?= fixtures/policies/basic.lpf
OBSERVED   ?= fixtures/nftables/basic.nft
REMOTE     ?= remote-linux
REMOTE_DIR ?= /tmp/lpf-remote-check

# Docker image tags
DOCKER_DISTROS     ?= debian ubuntu-22 ubuntu-24 alpine fedora
DOCKER_CI_TAG      ?= lpf-ci
DOCKER_CI_FILE     ?= Dockerfile.ci
DOCKER_BASES       := debian=ocaml/opam:debian-12-ocaml-5.1 \
                      ubuntu-22=ocaml/opam:ubuntu-22.04-ocaml-5.1 \
                      ubuntu-24=ocaml/opam:ubuntu-24.04-ocaml-5.1 \
                      alpine=ocaml/opam:alpine-ocaml-5.1 \
                      fedora=ocaml/opam:fedora-41-ocaml-5.1

# Ansible
ANSIBLE_PLAYBOOKS  ?= ansible/playbooks
ANSIBLE_ROLE       ?= ansible/roles/lpf

.PHONY: all help deps build test check ci clean install uninstall
.PHONY: man-generate man-check man-install
.PHONY: policy-check policy-fmt policy-fmt-check fixture-check
.PHONY: plan rules-show rules-diff remote-check
.PHONY: release-checksums release-sign release-verify
.PHONY: static deb rpm
.PHONY: bpf bpf-e2e bpf-e2e-comprehensive bpf-e2e-vagabond bpf-e2e-ct
.PHONY: docker docker-clean docker-test docker-feature docker-ebpf
.PHONY: ansible-check ansible-lint ansible-dry-run
.PHONY: e2e-feature e2e-ebpf
.PHONY: docker-pkg-deb docker-pkg-rpm docker-pkg-bin docker-pkg-cni
.PHONY: docker-pkg docker-pkg-cni-image packages

all: build

help: ## Show this help
	@printf '%s\n' 'lpf make targets:'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-28s\033[0m %s\n", $$1, $$2}'

# ── Core ──────────────────────────────────────────────────────────────────

deps: ## Install opam dependencies for build and tests
	$(OPAM) install . --deps-only --with-test

build: ## Build the OCaml library and CLI
	$(DUNE) build

static: ## Build a statically-linked binary
	$(DUNE) build --profile=static bin/main.exe

test: ## Run the Dune test suite
	$(DUNE) runtest

check: build test man-check fixture-check rules-diff ## Full CI check

ci: check ## Alias for check (full CI pipeline)

clean: ## Remove Dune build output
	$(DUNE) clean

install: ## Install lpf to PREFIX
	$(DUNE) build @install
	$(DUNE) install

uninstall: ## Uninstall lpf
	$(DUNE) uninstall

# ── Man pages ─────────────────────────────────────────────────────────────

man-generate: ## Regenerate man pages from OCaml metadata
	$(LPF) man generate --dir $(MAN_DIR)

man-check: ## Verify generated man pages are current
	$(LPF) man check --dir $(MAN_DIR)

man-install: ## Install man pages under PREFIX
	$(LPF) man install --prefix $(PREFIX)

# ── Policy operations ─────────────────────────────────────────────────────

policy-check: ## Run lpf check on POLICY
	$(LPF) check $(POLICY)

policy-fmt: ## Print formatted POLICY
	$(LPF) fmt $(POLICY)

policy-fmt-check: ## Verify POLICY is already formatted
	$(LPF) fmt --check $(POLICY)

fixture-check: ## Run lpf check on all valid policy fixtures
	@set -eu; \
	for policy in fixtures/policies/*.lpf; do \
		case "$$policy" in \
			*invalid*) continue ;; \
		esac; \
		printf 'checking %s\n' "$$policy"; \
		$(LPF) check "$$policy" >/dev/null; \
	done

plan: ## Print JSON plan for POLICY
	$(LPF) plan --json $(POLICY)

rules-show: ## Render nftables rules for POLICY
	$(LPF) rules show $(POLICY)

rules-diff: ## Diff OBSERVED ruleset against POLICY
	$(LPF) rules diff --observed $(OBSERVED) $(POLICY)

remote-check: ## Run build/test/man-check on REMOTE (SSH host)
	git archive --format=tar HEAD | ssh $(REMOTE) \
		'set -eu; rm -rf "$(REMOTE_DIR)"; mkdir -p "$(REMOTE_DIR)"; \
		 tar -xf - -C "$(REMOTE_DIR)"; cd "$(REMOTE_DIR)"; \
		 dune build; dune runtest; dune exec -- lpf man check'

# ── Docker ────────────────────────────────────────────────────────────────

docker: ## Build CI images for all 5 distros
	@for distro in $(DOCKER_DISTROS); do \
		base=$$(printf '%s\n' $(DOCKER_BASES) | grep "^$$distro=" | cut -d= -f2-); \
		[ -z "$$base" ] && continue; \
		printf 'building lpf-ci:%s from %s\n' "$$distro" "$$base"; \
		$(DUNE) build bin/main.exe 2>/dev/null || true; \
		docker build -f $(DOCKER_CI_FILE) \
			--build-arg BASE="$$base" \
			-t $(DOCKER_CI_TAG):$$distro .; \
	done

docker-clean: ## Remove lpf CI images
	@for distro in $(DOCKER_DISTROS); do \
		docker rmi $(DOCKER_CI_TAG):$$distro 2>/dev/null || true; \
	done

docker-test: docker ## Run dune runtest in all distro images
	@for distro in $(DOCKER_DISTROS); do \
		printf 'testing lpf-ci:%s\n' "$$distro"; \
		docker run --rm $(DOCKER_CI_TAG):$$distro opam exec -- dune runtest; \
	done

docker-feature: docker ## Run feature suite in all distro images
	@for distro in $(DOCKER_DISTROS); do \
		printf 'feature suite on lpf-ci:%s\n' "$$distro"; \
		docker run --rm $(DOCKER_CI_TAG):$$distro \
			bash -lc "cd /home/opam/src && ci/vagabond/feature-suite.sh"; \
	done

docker-ebpf: docker ## Run eBPF suite in privileged container (debian only)
	docker run --rm --privileged --user root \
		-v /sys/fs/bpf:/sys/fs/bpf \
		-v /sys/kernel/btf:/sys/kernel/btf:ro \
		--tmpfs /tmp \
		$(DOCKER_CI_TAG):debian \
		bash -lc "cd /home/opam/src && LPF_EBPF_LAYERS=0,1,2,3 ci/vagabond/ebpf-e2e-suite.sh"

# ── Ansible ───────────────────────────────────────────────────────────────

ansible-check: ## Syntax-check all Ansible playbooks
	@for pb in $(ANSIBLE_PLAYBOOKS)/*.yml; do \
		printf 'syntax check: %s\n' "$$pb"; \
		ansible-playbook --syntax-check "$$pb"; \
	done

ansible-lint: ## Lint the Ansible role
	ansible-lint $(ANSIBLE_ROLE) || true

ansible-dry-run: ## Dry-run the install playbook locally
	ansible-playbook -i localhost, -c local $(ANSIBLE_PLAYBOOKS)/install.yml \
		-e lpf_install_method=binary -e lpf_apply_dry_run=true \
		-e lpf_watchdog_enabled=false --check

ansible: ansible-check ansible-lint ansible-dry-run ## Run full Ansible validation

# ── eBPF ──────────────────────────────────────────────────────────────────

bpf: ## Build eBPF datapath object (Linux + clang/llvm + BTF required)
	sh bpf/build.sh

bpf-e2e: bpf ## Basic eBPF E2E: prog_test_run verdict check
	rm -rf /sys/fs/bpf/lpftest && mkdir -p /sys/fs/bpf/lpftest/prog
	bpftool prog loadall bpf/lpf_kern.o /sys/fs/bpf/lpftest/prog \
		pinmaps /sys/fs/bpf/lpftest
	python3 bpf/e2e_progrun.py; status=$$?; \
	rm -rf /sys/fs/bpf/lpftest; exit $$status

bpf-e2e-comprehensive: bpf ## 4-layer E2E: prog_test_run + map state + toolchain + live traffic
	rm -rf /sys/fs/bpf/lpftest && mkdir -p /sys/fs/bpf/lpftest/prog
	bpftool prog loadall bpf/lpf_kern.o /sys/fs/bpf/lpftest/prog \
		pinmaps /sys/fs/bpf/lpftest
	python3 bpf/e2e_runner.py \
		--layers $${LPF_EBPF_LAYERS:-0,1,2,3} --skip-build; \
	status=$$?; rm -rf /sys/fs/bpf/lpftest; exit $$status

bpf-e2e-vagabond: ## Full Vagabond eBPF E2E suite (Firecracker microVM)
	ci/vagabond/ebpf-e2e-suite.sh

bpf-e2e-ct: bpf ## eBPF conntrack-specific E2E
	ci/vagabond/ebpf-conntrack-suite.sh

# ── E2E suites (requires Docker) ──────────────────────────────────────────

e2e-feature: docker ## Run feature suite on all 5 distros
	ci/vagabond/ansible-suite.sh

e2e-ebpf: docker ## Run eBPF suite on all 5 distros (privileged)
	@for distro in $(DOCKER_DISTROS); do \
		printf 'ebpf E2E on lpf-ci:%s\n' "$$distro"; \
		docker run --rm --privileged --user root \
			-v /sys/fs/bpf:/sys/fs/bpf \
			-v /sys/kernel/btf:/sys/kernel/btf:ro \
			--tmpfs /tmp \
			$(DOCKER_CI_TAG):$$distro \
			bash -lc "cd /home/opam/src && LPF_EBPF_STRICT=1 ci/vagabond/ebpf-e2e-suite.sh" \
			|| echo "ebpf E2E on $$distro had issues (may lack kernel support)"; \
	done

# ── Release ───────────────────────────────────────────────────────────────

RELEASE_VERSION ?= $(shell $(LPF) version)
RELEASE_TARBALL ?= lpf-$(RELEASE_VERSION).tar.gz
CHECKSUM_FILE   ?= SHA256SUMS
SIGN_KEY        ?=

release-checksum: ## Generate release tarball and checksums
	git archive --prefix=lpf-$(RELEASE_VERSION)/ -o $(RELEASE_TARBALL) HEAD
	sha256sum $(RELEASE_TARBALL) > $(CHECKSUM_FILE)
	@printf 'checksums written to %s\n' $(CHECKSUM_FILE)

release-sign: release-checksum ## Sign release files with GPG
	@if [ -z "$(SIGN_KEY)" ]; then \
		printf 'set SIGN_KEY to your GPG key ID\n'; exit 1; fi
	gpg --detach-sign --armor --local-user $(SIGN_KEY) $(CHECKSUM_FILE)
	gpg --detach-sign --armor --local-user $(SIGN_KEY) $(RELEASE_TARBALL)
	@printf 'signed %s and %s with key %s\n' \
		$(RELEASE_TARBALL) $(CHECKSUM_FILE) $(SIGN_KEY)

release-verify: ## Verify release checksums and signatures
	sha256sum -c $(CHECKSUM_FILE)
	@if [ -f $(CHECKSUM_FILE).asc ]; then gpg --verify $(CHECKSUM_FILE).asc; fi
	@if [ -f $(RELEASE_TARBALL).asc ]; then gpg --verify $(RELEASE_TARBALL).asc; fi
	@printf 'release verified\n'

deb: ## Build Debian package (local, requires dpkg-buildpackage)
	set -eu; rm -rf debian; cp -a packaging/deb debian; \
	trap 'rm -rf debian' EXIT; dpkg-buildpackage -b -us -uc -d

rpm: ## Build RPM package (local, requires rpmbuild)
	set -eu; VERSION=$$($(LPF) version); \
	RPM_TOPDIR="$$(pwd)/../lpf-rpmbuild"; \
	OPAMSWITCH="$$(opam switch show)"; export OPAMSWITCH; \
	rm -rf "$$RPM_TOPDIR"; \
	mkdir -p "$$RPM_TOPDIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}; \
	git archive --prefix="lpf-$$VERSION/" \
		-o "$$RPM_TOPDIR/SOURCES/lpf-$$VERSION.tar.gz" HEAD; \
	rpmbuild -bb --nodeps packaging/rpm/lpf.spec \
		--define "_topdir $$RPM_TOPDIR"

# ── Packaging via Docker (all 5 distros + CNI) ──────────────────────────

PKG_OUT     ?= _packages
DEB_DISTROS := debian ubuntu-22 ubuntu-24
RPM_DISTROS := fedora
BIN_DISTROS := debian ubuntu-22 ubuntu-24 alpine fedora

docker-pkg-deb: docker ## Build .deb packages inside Docker for Debian/Ubuntu
	@mkdir -p $(PKG_OUT)/deb
	@for distro in $(DEB_DISTROS); do \
		if ! docker image inspect $(DOCKER_CI_TAG):$$distro >/dev/null 2>&1; then \
			printf 'image %s:%s not found, skipping\n' "$(DOCKER_CI_TAG)" "$$distro"; \
			continue; \
		fi; \
		printf 'building .deb in %s:%s\n' "$(DOCKER_CI_TAG)" "$$distro"; \
		docker run --rm --user root \
			-v "$(PWD)/$(PKG_OUT):/output" \
			$(DOCKER_CI_TAG):$$distro \
			bash -lc 'set -eu; cd /home/opam/src; \
				rm -rf debian; cp -a packaging/deb debian; \
				DEB_VERSION=$$(opam exec -- dune exec -- lpf version); \
				sed -i "s/(0\.[0-9.]*)/($$DEB_VERSION)/" debian/changelog; \
				mkdir -p /tmp/debbuild; \
				cp -a . /tmp/debbuild/lpf-$$DEB_VERSION; \
				cd /tmp/debbuild/lpf-$$DEB_VERSION; \
				export OPAMSWITCH=$$(opam switch show); \
				dpkg-buildpackage -b -us -uc -d; \
				cp /tmp/debbuild/*.deb /output/deb/; \
				printf "  -> %s\n" $$(ls /tmp/debbuild/*.deb)'; \
	done
	@printf 'DEB packages in %s/deb/\n' '$(PKG_OUT)'

docker-pkg-rpm: docker ## Build .rpm packages inside Docker for Fedora
	@mkdir -p $(PKG_OUT)/rpm
	@for distro in $(RPM_DISTROS); do \
		if ! docker image inspect $(DOCKER_CI_TAG):$$distro >/dev/null 2>&1; then \
			printf 'image %s:%s not found, skipping\n' "$(DOCKER_CI_TAG)" "$$distro"; \
			continue; \
		fi; \
		printf 'building .rpm in %s:%s\n' "$(DOCKER_CI_TAG)" "$$distro"; \
		docker run --rm --user root \
			-v "$(PWD)/$(PKG_OUT):/output" \
			$(DOCKER_CI_TAG):$$distro \
			bash -lc 'set -eu; cd /home/opam/src; \
				RPM_VERSION=$$(opam exec -- dune exec -- lpf version); \
				RPM_TOPDIR="/tmp/rpmbuild"; \
				rm -rf "$$RPM_TOPDIR"; \
				mkdir -p "$$RPM_TOPDIR"/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}; \
				git config --global --add safe.directory /home/opam/src; \
				git archive --prefix="lpf-$$RPM_VERSION/" \
					-o "$$RPM_TOPDIR/SOURCES/lpf-$$RPM_VERSION.tar.gz" HEAD; \
				sed "s/^Version:.*/Version: $$RPM_VERSION/" packaging/rpm/lpf.spec \
					> "$$RPM_TOPDIR/SPECS/lpf.spec"; \
				rpmbuild -bb --nodeps "$$RPM_TOPDIR/SPECS/lpf.spec" \
					--define "_topdir $$RPM_TOPDIR"; \
				cp "$$RPM_TOPDIR"/RPMS/*/*.rpm /output/rpm/ 2>/dev/null || true; \
				printf "  -> %s\n" $$(ls "$$RPM_TOPDIR"/RPMS/*/*.rpm 2>/dev/null || echo none)'; \
	done
	@printf 'RPM packages in %s/rpm/\n' '$(PKG_OUT)'

docker-pkg-bin: docker ## Extract statically-linked lpf binary from each distro image
	@mkdir -p $(PKG_OUT)/bin
	@for distro in $(BIN_DISTROS); do \
		if ! docker image inspect $(DOCKER_CI_TAG):$$distro >/dev/null 2>&1; then \
			printf 'image %s:%s not found, skipping\n' "$(DOCKER_CI_TAG)" "$$distro"; \
			continue; \
		fi; \
		printf 'extracting binary from %s:%s\n' "$(DOCKER_CI_TAG)" "$$distro"; \
		docker run --rm \
			-v "$(PWD)/$(PKG_OUT):/output" \
			$(DOCKER_CI_TAG):$$distro \
			bash -lc 'set -eu; \
				VERSION=$$(opam exec -- dune exec -- lpf version); \
				cp /usr/local/bin/lpf /output/bin/lpf-$$VERSION-'$$distro'; \
				printf "  -> lpf-$$VERSION-'$$distro'\n"'; \
	done
	@printf 'Binaries in %s/bin/\n' '$(PKG_OUT)'

docker-pkg-cni: docker ## Build CNI plugin binary inside Docker and package as tarball
	@mkdir -p $(PKG_OUT)/cni
	@printf 'building CNI plugin in %s:debian\n' "$(DOCKER_CI_TAG)"
	@docker run --rm --user root \
		-v "$(PWD)/$(PKG_OUT):/output" \
		$(DOCKER_CI_TAG):debian \
		bash -lc 'set -eu; cd /home/opam/src; \
			opam exec -- dune build bin/cni/main.exe; \
			VERSION=$$(opam exec -- dune exec -- lpf version); \
			cp _build/default/bin/cni/main.exe /output/cni/lpf-cni-$$VERSION-linux-amd64; \
			chmod +x /output/cni/lpf-cni-$$VERSION-linux-amd64; \
			printf "  -> lpf-cni-$$VERSION-linux-amd64\n"'
	@printf 'CNI binary in %s/cni/\n' '$(PKG_OUT)'

docker-pkg-cni-image: docker-pkg-cni ## Build CNI Docker image
	@printf 'building CNI Docker image\n'
	@mkdir -p $(PKG_OUT)/cni-docker
	@cp $(PKG_OUT)/cni/lpf-cni-*-linux-amd64 $(PKG_OUT)/cni-docker/lpf-cni 2>/dev/null || true
	@cp bpf/lpf_kern.o $(PKG_OUT)/cni-docker/lpf_kern.o 2>/dev/null || true
	@docker build -f Dockerfile.cni -t lpf-cni:latest $(PKG_OUT)/cni-docker/ 2>/dev/null || \
		docker build -f Dockerfile.cni -t lpf-cni:latest . 2>/dev/null || true
	@printf 'CNI image: lpf-cni:latest\n'

docker-pkg: docker-pkg-deb docker-pkg-rpm docker-pkg-bin docker-pkg-cni ## Build all packages via Docker
	@printf '\nAll packages in %s/\n' '$(PKG_OUT)'
	@find $(PKG_OUT) -type f | sort

packages: docker-pkg ## Alias for docker-pkg (build all packages)
