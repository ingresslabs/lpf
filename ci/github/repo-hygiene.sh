#!/usr/bin/env bash
set -euo pipefail

run_tool() {
  if command -v opam >/dev/null 2>&1; then
    opam exec -- "$@"
  else
    "$@"
  fi
}

run_tool dune exec -- lpf man check

commands=$(run_tool dune exec -- lpf help \
  | awk '
      /^Commands:/ { in_commands = 1; next }
      in_commands && /^$/ { exit }
      in_commands && /^  [a-z][a-z0-9-]+[[:space:]]/ { print $1 }
    ' \
  | grep -Ev '^(version|help)$')

missing_docs=0
for command in $commands; do
  if ! grep -Eq "lpf ${command}([[:space:]\`<]|$)" docs/COMMANDS.md; then
    echo "::error::docs/COMMANDS.md does not mention lpf ${command}"
    missing_docs=1
  fi
done
if [ "$missing_docs" -ne 0 ]; then
  exit 1
fi

awk -F '\t' '
  /^#/ || NF == 0 { next }
  NF < 7 {
    printf "::error file=ci/kernels/kernel-matrix.tsv,line=%d::expected at least 7 tab-separated fields\n", NR
    bad = 1
  }
  seen[$1]++ {
    printf "::error file=ci/kernels/kernel-matrix.tsv,line=%d::duplicate kernel label %s\n", NR, $1
    bad = 1
  }
  $1 !~ /^[A-Za-z0-9_.-]+$/ {
    printf "::error file=ci/kernels/kernel-matrix.tsv,line=%d::unsafe kernel label %s\n", NR, $1
    bad = 1
  }
  END { exit bad }
' ci/kernels/kernel-matrix.tsv

ipv4='([0-9]{1,3}\.){3}[0-9]{1,3}'
if git grep -nI -E \
  "(root@${ipv4}|HostName[[:space:]]+${ipv4}|BEGIN (OPENSSH|RSA|EC) PRIVATE KEY)" \
  -- .; then
  echo "::error::tracked files contain lab host literals or private key material"
  exit 1
fi

if bad_files=$(git ls-files | while IFS= read -r path; do
  [ -e "$path" ] || continue
  printf '%s\n' "$path"
done | grep -E '(^ci/jenkins/|(^|/)(aero-install-support-[0-9-]+\.json|create_job[0-9]*\.py|disable_csrf\.groovy|security\.groovy|mini-e2e\.xml|lpf-[0-9a-f].*\.tar\.gz|lpf-firecracker.*\.xml|jenkins-.*\.(xml|json))$)' || true); then
  if [ -n "$bad_files" ]; then
    echo "::error::transient lab/helper artifacts are tracked"
    printf '%s\n' "$bad_files"
    exit 1
  fi
fi
