FROM ocaml/opam:ubuntu-22.04-ocaml-5.1 AS builder

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

RUN opam install . --deps-only --with-test --yes \
 && opam exec -- dune build

FROM ubuntu:22.04 AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 nftables conntrack \
 && rm -rf /var/lib/apt/lists/*

COPY --from=builder /home/opam/src/_build/default/bin/main.exe /usr/local/bin/lpf
COPY --from=builder /home/opam/src/bin/lpf-completion.sh /etc/bash_completion.d/lpf

RUN echo "source /etc/bash_completion.d/lpf" >> /etc/bash.bashrc

ENTRYPOINT ["/usr/local/bin/lpf"]
CMD ["help"]
