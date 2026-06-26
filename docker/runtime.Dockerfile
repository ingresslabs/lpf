# lpf runtime image — ships a pre-built lpf binary on a minimal base.
#
# Multi-stage: builder compiles from source, runtime copies the static binary.
# The runtime stage contains only iproute2, nftables, conntrack (runtime deps).
#
#   docker build -f docker/runtime.Dockerfile -t lpf:latest .
#   docker run --rm --privileged lpf help

FROM ocaml/opam:debian-12-ocaml-5.1 AS builder

USER root
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables conntrack \
 && rm -rf /var/lib/apt/lists/*

USER opam
WORKDIR /home/opam/src
COPY --chown=opam:opam lpf.opam Makefile dune-project dune .ocamlformat ./
COPY --chown=opam:opam bin/ ./bin/
COPY --chown=opam:opam lib/ ./lib/
COPY --chown=opam:opam test/ ./test/
COPY --chown=opam:opam man/ ./man/
COPY --chown=opam:opam configs/ ./configs/
COPY --chown=opam:opam fixtures/ ./fixtures/

RUN opam install . --deps-only --with-test --yes \
 && opam exec -- dune build


FROM ubuntu:22.04 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables conntrack ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /home/opam/src/_build/default/bin/main.exe /usr/local/bin/lpf
COPY --from=builder /home/opam/src/bin/lpf-completion.sh /etc/bash_completion.d/lpf
COPY --from=builder /home/opam/src/man/generated/ /usr/local/share/man/man1/

RUN echo "source /etc/bash_completion.d/lpf" >> /etc/bash.bashrc

ENV LPF_VAR_DIR=/var/lib/lpf
ENTRYPOINT ["/usr/local/bin/lpf"]
CMD ["help"]
