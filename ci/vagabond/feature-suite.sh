#!/usr/bin/env bash
# Comprehensive lpf userspace feature suite, designed to run inside an isolated
# Vagabond Linux sandbox (nomad.container) across different base images.
#
# Covers all userspace feature areas: parse/check, formatting, semantic plan,
# nftables/tc/routing/sysctl backends, NAT/RDR, packet explainability, policy
# test assertions, generated man pages, AI tool schemas, and shell completions.
# Kernel/eBPF datapath conformance lives in ebpf-suite.sh (Firecracker microVM).
#
# Exits non-zero on any failure and writes junit-lpf-feature.xml so the Vagabond
# job (and Jenkins) gate on the result.
set -uo pipefail

# Work whether the image ships an installed lpf binary or an opam/dune env.
eval "$(opam env 2>/dev/null)" || true
if command -v lpf >/dev/null 2>&1; then
  RUN_LPF="lpf"
else
  RUN_LPF="dune exec -- lpf"
fi
lpf() { $RUN_LPF "$@"; }

step_index=0
failure_count=0
cases=""
junit_file="${LPF_FEATURE_JUNIT:-junit-lpf-feature.xml}"

xml_escape() { printf '%s' "$1" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' -e 's/"/\&quot;/g'; }

run_step() {
  name="$1"; shift
  step_index=$((step_index + 1))
  printf 'step %02d: %s\n' "$step_index" "$name"
  out="$(bash -c "$*" 2>&1)"; status=$?
  esc_name="$(xml_escape "$name")"
  if [ "$status" -ne 0 ]; then
    failure_count=$((failure_count + 1))
    printf '  FAIL (%s)\n%s\n' "$status" "$out" | sed 's/^/    /'
    cases="$cases    <testcase classname=\"lpf.feature\" name=\"$esc_name\"><failure>$(xml_escape "$out")</failure></testcase>\n"
  else
    cases="$cases    <testcase classname=\"lpf.feature\" name=\"$esc_name\"/>\n"
  fi
}

# --- parse / validate -------------------------------------------------------
run_step "version reports semver" 'lpf version | grep -Eq "^[0-9]+\.[0-9]+\.[0-9]+"'
run_step "help lists check" 'lpf help | grep -q "check"'
run_step "basic policy validates as JSON" 'lpf check --json fixtures/policies/basic.lpf | grep -q "\"valid\":true"'
run_step "invalid syntax is rejected" '! lpf check fixtures/policies/invalid-syntax.lpf'
run_step "all non-invalid fixtures validate" '
  set -e
  for p in fixtures/policies/*.lpf; do
    case "$p" in *invalid*) continue ;; esac
    lpf check "$p" >/dev/null
  done'

# --- formatting -------------------------------------------------------------
run_step "fmt --check accepts formatted policy" 'lpf fmt --check fixtures/policies/basic.lpf | grep -q "is formatted"'
run_step "fmt normalizes messy policy" 'lpf fmt fixtures/policies/messy.lpf | grep -q "set default deny"'

# --- semantic plan ----------------------------------------------------------
run_step "plan includes checksum" 'lpf plan --json fixtures/policies/basic.lpf | grep -q "\"checksum\":\"md5:"'
run_step "plan preserves default deny" 'lpf plan --json fixtures/policies/basic.lpf | grep -q "\"default_action\":\"deny\""'

# --- backends: nftables / tc / routing / sysctl -----------------------------
run_step "nftables renderer emits filter table" 'lpf rules show fixtures/policies/basic.lpf | grep -q "table inet lpf_filter"'
run_step "nftables diff: no changes on baseline" 'lpf rules diff --observed fixtures/nftables/basic.nft fixtures/policies/basic.lpf | grep -q "no changes"'
run_step "nftables diff: detects changes" 'lpf rules diff --observed fixtures/nftables-diff/changed-rule.diff fixtures/policies/basic.lpf | grep -q "changes required"'
run_step "tc backend renders qdisc plan" 'lpf plan --backend tc fixtures/policies/queue-route.lpf | grep -q "tc qdisc add"'
run_step "routing backend renders fwmark rule" 'lpf plan --backend routing fixtures/policies/queue-route.lpf | grep -q "ip rule add fwmark"'
run_step "sysctl diff emits JSON status" 'lpf diff --backend sysctl --json fixtures/policies/basic.lpf | grep -q "\"backend\":\"sysctl\""'

# --- NAT / RDR --------------------------------------------------------------
run_step "nat/rdr policy validates" 'lpf check --json fixtures/policies/nat-rdr.lpf | grep -q "\"valid\":true"'
run_step "nat/rdr rules include dnat" 'lpf rules show fixtures/policies/nat-rdr.lpf | grep -q "dnat ip to 10.0.0.5:8080"'

# --- explainability ---------------------------------------------------------
run_step "explain: trusted ssh pass" 'lpf explain in eth0 from 10.0.0.5 to 192.168.1.1 proto tcp port 22 fixtures/policies/exhaustive.lpf | grep -q "Decision: pass"'
run_step "explain: untrusted ssh block" 'lpf explain in eth0 from 8.8.8.8 to 10.0.0.10 proto tcp port 22 fixtures/policies/exhaustive.lpf | grep -q "Decision: block"'

# --- policy test assertions -------------------------------------------------
run_step "policy test assertions pass (junit)" 'lpf test --junit junit-lpf-policy.xml fixtures/tests/exhaustive.lpf.test | grep -q "OK:"'

# --- generated man pages ----------------------------------------------------
run_step "generated man pages are current" 'lpf man check --dir man/generated | grep -q "checked"'

# --- AI tool schemas --------------------------------------------------------
run_step "openai tool schemas include check" 'lpf tools --format openai | grep -q "\"name\":\"check\""'
run_step "jsonschema tool schemas include lpf-check" 'lpf tools --format jsonschema | grep -q "lpf-check"'
run_step "system prompt mentions firewall automation" 'lpf tools --format system-prompt | grep -q "firewall automation agent"'

# --- shell completions ------------------------------------------------------
run_step "bash completion defines command helper" 'lpf completion bash | grep -q "_lpf_commands"'
run_step "zsh completion defines compdef" 'lpf completion zsh | grep -q "#compdef lpf"'
run_step "fish completion defines lpf completes" 'lpf completion fish | grep -q "complete -c lpf"'

# --- guarded apply (dry-run, no host mutation) ------------------------------
run_step "apply --dry-run reports plan checksum" 'lpf apply --dry-run fixtures/policies/basic.lpf | grep -q "dry-run: plan checksum"'

# --- junit + result ---------------------------------------------------------
{
  printf '<?xml version="1.0" encoding="UTF-8"?>\n<testsuites>\n'
  printf '  <testsuite name="lpf-feature" tests="%s" failures="%s">\n' "$step_index" "$failure_count"
  printf '%b' "$cases"
  printf '  </testsuite>\n</testsuites>\n'
} > "$junit_file"

printf '\nfeature-suite: %s steps, %s failures (image=%s)\n' "$step_index" "$failure_count" "$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")"
[ "$failure_count" -eq 0 ]
