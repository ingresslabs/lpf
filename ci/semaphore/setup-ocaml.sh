#!/usr/bin/env bash
set -euo pipefail

compiler="${LPF_OCAML_COMPILER:-5.2.1}"
switch="${LPF_OPAM_SWITCH:-lpf-ci-${compiler}}"

export OPAMYES=true
export OPAMERRLOGLEN="${OPAMERRLOGLEN:-0}"

if ! opam switch list --short 2>/dev/null | grep -Fxq "$switch"; then
  opam switch create "$switch" "ocaml-base-compiler.${compiler}" --yes
fi

eval "$(opam env --switch="$switch" --set-switch)"

opam install . --deps-only --with-test --yes

printf 'ocaml: '
ocamlc -version
printf 'dune: '
dune --version
