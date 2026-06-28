# lpf eBPF development image — full eBPF toolchain with BTF and kernel headers.
#
# Unlike the CI image (which omits eBPF tooling), this image
# requires the eBPF build toolchain and ships libbpf, bpftool, clang/llvm,
# and kernel BTF headers. Used for local eBPF datapath development and
# for producing verified BPF objects.
#
#   docker build -f docker/ebpf.Dockerfile -t lpf-ebpf:latest .
#   docker run --rm --privileged \
#     -v /sys/fs/bpf:/sys/fs/bpf \
#     -v /sys/kernel/btf:/sys/kernel/btf:ro \
#     lpf-ebpf:latest \
#     bash -lc "cd /home/opam/src && make bpf && ci/vagabond/ebpf-suite.sh"

FROM ocaml/opam:debian-12-ocaml-5.1 AS builder

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash make python3 ca-certificates \
    iproute2 nftables conntrack iperf3 \
    clang llvm libbpf-dev bpftool linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*

RUN mkdir -p /home/opam/src && chown opam:opam /home/opam/src

USER opam
WORKDIR /home/opam/src
COPY --chown=opam:opam . .
RUN rm -rf _build && \
    opam install . --deps-only --with-test --yes && \
    opam exec -- dune build && \
    sudo install -m 0755 _build/default/bin/main.exe /usr/local/bin/lpf && \
    make bpf

ENV LPF_VAR_DIR=/tmp/lpf
ENV LPF_EBPF_STRICT=1
CMD ["bash", "-lc", "lpf help"]
