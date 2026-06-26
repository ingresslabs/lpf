# lpf CI image — parametric per-distro build for the 5-distro test matrix.
#
# Supports 5 Linux userspaces via build arg BASE:
#   debian:    ocaml/opam:debian-12-ocaml-5.1          (apt)
#   ubuntu-22: ocaml/opam:ubuntu-22.04-ocaml-5.1       (apt)
#   ubuntu-24: ocaml/opam:ubuntu-24.04-ocaml-5.1       (apt)
#   alpine:    ocaml/opam:alpine-ocaml-5.1             (apk)
#   fedora:    ocaml/opam:fedora-41-ocaml-5.1          (dnf)
#
# Includes userspace toolchain (bash, iproute2, nftables, conntrack) and
# best-effort eBPF toolchain (clang, llvm, libbpf, bpftool). eBPF failures
# are non-fatal — the eBPF suite degrades gracefully if tooling is absent.
#
# Usage:
#   docker build -f docker/ci.Dockerfile \
#     --build-arg BASE=ocaml/opam:debian-12-ocaml-5.1 \
#     -t lpf-ci:debian .

ARG BASE=ocaml/opam:debian-12-ocaml-5.1
FROM ${BASE} AS ci

USER root
RUN if command -v apt-get >/dev/null 2>&1; then \
      apt-get update && \
      apt-get install -y --no-install-recommends bash make python3 ca-certificates iproute2 nftables conntrack && \
      (apt-get install -y --no-install-recommends clang llvm libbpf-dev bpftool || true) && \
      rm -rf /var/lib/apt/lists/*; \
    elif command -v dnf >/dev/null 2>&1; then \
      dnf install -y bash make python3 ca-certificates iproute iproute-tc nftables conntrack-tools && \
      (dnf install -y clang llvm libbpf-devel bpftool || true) && \
      dnf clean all; \
    elif command -v apk >/dev/null 2>&1; then \
      apk add --no-cache bash make python3 ca-certificates iproute2 nftables conntrack-tools && \
      (apk add --no-cache clang llvm libbpf-dev bpftool || true); \
    fi

RUN mkdir -p /home/opam/src && chown opam:opam /home/opam/src

USER opam
WORKDIR /home/opam/src
COPY --chown=opam:opam . .
RUN rm -rf _build && \
    opam install . --deps-only --with-test --yes && \
    opam exec -- dune build && \
    sudo install -m 0755 _build/default/bin/main.exe /usr/local/bin/lpf

ENV LPF_VAR_DIR=/tmp/lpf
CMD ["bash", "-lc", "lpf help"]
