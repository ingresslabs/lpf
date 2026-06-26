# lpf Firecracker rootfs builder — produces a rootfs image for Firecracker
# microVMs used in the kernel matrix and E2E test stages.
#
# The output is a root filesystem tarball suitable for use as a Firecracker
# rootfs. Includes lpf, OCaml runtime, userspace tooling, and eBPF toolchain.
#
#   docker build -f docker/rootfs.Dockerfile -t lpf-rootfs:latest .
#   docker run --rm --privileged lpf-rootfs:latest > lpf-rootfs.ext4
#
# Or export the filesystem directly:
#   container_id=$(docker create lpf-rootfs:latest)
#   docker export $container_id | gzip > lpf-rootfs.tar.gz
#   docker rm $container_id

FROM ocaml/opam:debian-12-ocaml-5.1 AS builder

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    bash make python3 ca-certificates openssh-server \
    iproute2 nftables conntrack iperf3 \
    clang llvm libbpf-dev bpftool linux-libc-dev \
 && rm -rf /var/lib/apt/lists/*

# Firecracker rootfs conventions
RUN mkdir -p /home/opam/src && chown opam:opam /home/opam/src \
 && echo 'root:root' | chpasswd \
 && ssh-keygen -A

USER opam
WORKDIR /home/opam/src
COPY --chown=opam:opam . .
RUN rm -rf _build && \
    opam install . --deps-only --with-test --yes && \
    opam exec -- dune build && \
    sudo install -m 0755 _build/default/bin/main.exe /usr/local/bin/lpf && \
    make bpf

# init script for Firecracker
USER root
COPY docker/rootfs-init.sh /sbin/init
RUN chmod 0755 /sbin/init

ENV LPF_VAR_DIR=/tmp/lpf
CMD ["/sbin/init"]
