#!/usr/bin/env bash
set -uo pipefail
shopt -u patsub_replacement 2>/dev/null || true

expected_steps=30
step_index=0
failure_count=0
cases_file="$(mktemp)"
log_dir="${LPF_FUNCTIONAL_LOG_DIR:-reports/functional}"
junit_file="${LPF_FUNCTIONAL_JUNIT:-junit-lpf-functional.xml}"

mkdir -p "$log_dir"

lpf() {
  dune exec -- lpf "$@"
}
export -f lpf

xml_escape() {
  local value="$1"
  value="${value//&/&amp;}"
  value="${value//</&lt;}"
  value="${value//>/&gt;}"
  value="${value//\"/&quot;}"
  value="${value//\'/&apos;}"
  printf '%s' "$value"
}

slug() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]' | sed -E 's/[^a-z0-9]+/-/g; s/^-//; s/-$//'
}

record_case() {
  local name="$1"
  local status="$2"
  local elapsed="$3"
  local command_text="$4"
  local log_path="$5"
  local escaped_name escaped_command escaped_log

  escaped_name="$(xml_escape "$(printf '%02d %s' "$step_index" "$name")")"
  escaped_command="$(xml_escape "$command_text")"
  escaped_log="$(xml_escape "$(tail -n 120 "$log_path" 2>/dev/null)")"

  {
    printf '    <testcase classname="lpf.functional" name="%s" time="%s">\n' "$escaped_name" "$elapsed"
    if [ "$status" -ne 0 ]; then
      printf '      <failure message="command exited %s">%s</failure>\n' "$status" "$escaped_log"
    fi
    printf '      <system-out>command: %s\n%s</system-out>\n' "$escaped_command" "$escaped_log"
    printf '    </testcase>\n'
  } >>"$cases_file"
}

run_step() {
  local name="$1"
  shift
  local command_text="$*"
  local log_path
  local started elapsed status

  step_index=$((step_index + 1))
  log_path="$log_dir/$(printf '%02d' "$step_index")-$(slug "$name").log"
  printf 'step %02d/%02d: %s\n' "$step_index" "$expected_steps" "$name"

  started="$SECONDS"
  "$@" >"$log_path" 2>&1
  status=$?
  elapsed=$((SECONDS - started))

  if [ "$status" -ne 0 ]; then
    failure_count=$((failure_count + 1))
    printf '  failed with status %s; see %s\n' "$status" "$log_path" >&2
  fi

  record_case "$name" "$status" "$elapsed" "$command_text" "$log_path"
}

write_junit() {
  {
    printf '<?xml version="1.0" encoding="UTF-8"?>\n'
    printf '<testsuites>\n'
    printf '  <testsuite name="lpf-functional" tests="%s" failures="%s">\n' "$step_index" "$failure_count"
    cat "$cases_file"
    printf '  </testsuite>\n'
    printf '</testsuites>\n'
  } >"$junit_file"
}

run_step "version command reports semver" \
  bash -c 'lpf version | grep -Eq "^[0-9]+\\.[0-9]+\\.[0-9]+"'

run_step "top-level help lists check command" \
  bash -c 'lpf help | grep -q "check           parse and validate policy"'

run_step "rules command help is implemented" \
  bash -c 'lpf help rules | grep -q "Status: implemented"'

run_step "basic policy validates as JSON" \
  bash -c 'lpf check --json fixtures/policies/basic.lpf | grep -q "\"valid\":true"'

run_step "invalid syntax policy is rejected" \
  bash -c '! lpf check fixtures/policies/invalid-syntax.lpf'

run_step "formatted policy passes fmt check" \
  bash -c 'lpf fmt --check fixtures/policies/basic.lpf | grep -q "is formatted"'

run_step "messy policy formatter emits normalized policy" \
  bash -c 'lpf fmt fixtures/policies/messy.lpf | grep -q "set default deny"'

run_step "semantic plan includes checksum" \
  bash -c 'lpf plan --json fixtures/policies/basic.lpf | grep -q "\"checksum\":\"md5:"'

run_step "semantic plan preserves default deny" \
  bash -c 'lpf plan --json fixtures/policies/basic.lpf | grep -q "\"default_action\":\"deny\""'

run_step "nftables renderer emits filter table" \
  bash -c 'lpf rules show fixtures/policies/basic.lpf | grep -q "table inet lpf_filter"'

run_step "unchanged nftables fixture has no diff" \
  bash -c 'lpf rules diff --observed fixtures/nftables/basic.nft fixtures/policies/basic.lpf | grep -q "no changes"'

run_step "changed nftables fixture reports changes" \
  bash -c 'lpf rules diff --observed fixtures/nftables-diff/changed-rule.diff fixtures/policies/basic.lpf | grep -q "changes required"'

run_step "tc backend renders qdisc plan" \
  bash -c 'lpf plan --backend tc fixtures/policies/queue-route.lpf | grep -q "tc qdisc add"'

run_step "routing backend renders fwmark rule" \
  bash -c 'lpf plan --backend routing fixtures/policies/queue-route.lpf | grep -q "ip rule add fwmark"'

run_step "nat and rdr policy validates" \
  bash -c 'lpf check --json fixtures/policies/nat-rdr.lpf | grep -q "\"valid\":true"'

run_step "nat and rdr rules include dnat" \
  bash -c 'lpf rules show fixtures/policies/nat-rdr.lpf | grep -q "dnat ip to 10.0.0.5:8080"'

run_step "explain reports trusted ssh pass" \
  bash -c 'lpf explain in eth0 from 10.0.0.5 to 192.168.1.1 proto tcp port 22 fixtures/policies/exhaustive.lpf | grep -q "Decision: pass"'

run_step "explain reports untrusted ssh block" \
  bash -c 'lpf explain in eth0 from 8.8.8.8 to 10.0.0.10 proto tcp port 22 fixtures/policies/exhaustive.lpf | grep -q "Decision: block"'

run_step "exhaustive policy assertions pass with junit" \
  bash -c 'lpf test --junit junit-lpf-policy.xml fixtures/tests/exhaustive.lpf.test | grep -q "OK:"'

run_step "generated man pages are current" \
  bash -c 'lpf man check --dir man/generated | grep -q "checked"'

run_step "openai tool schemas include check" \
  bash -c 'lpf tools --format openai | grep -q "\"name\":\"check\""'

run_step "jsonschema tool schemas include lpf-check" \
  bash -c 'lpf tools --format jsonschema | grep -q "lpf-check"'

run_step "system prompt mentions firewall automation" \
  bash -c 'lpf tools --format system-prompt | grep -q "firewall automation agent"'

run_step "bash completion includes command helper" \
  bash -c 'lpf completion bash | grep -q "_lpf_commands"'

run_step "zsh completion includes compdef" \
  bash -c 'lpf completion zsh | grep -q "#compdef lpf"'

run_step "fish completion includes lpf commands" \
  bash -c 'lpf completion fish | grep -q "complete -c lpf"'

run_step "sysctl diff emits JSON status" \
  bash -c 'lpf diff --backend sysctl --json fixtures/policies/basic.lpf | grep -q "\"backend\":\"sysctl\""'

run_step "apply dry-run reports plan checksum" \
  bash -c 'lpf apply --dry-run fixtures/policies/basic.lpf | grep -q "dry-run: plan checksum"'

run_step "observed tc diff sees no changes" \
  bash -c 'tmp="$(mktemp)"; lpf plan --backend tc fixtures/policies/queue-route.lpf >"$tmp"; lpf diff --backend tc --observed "$tmp" fixtures/policies/queue-route.lpf | grep -q "no changes"; rm -f "$tmp"'

run_step "qemu boots host kernel smoke vm" \
  bash -c 'ci/semaphore/qemu-smoke.sh reports/qemu-smoke.log'

if [ "$step_index" -ne "$expected_steps" ]; then
  failure_count=$((failure_count + 1))
  printf 'expected %s steps, ran %s\n' "$expected_steps" "$step_index" >&2
fi

write_junit
rm -f "$cases_file"

if [ "$failure_count" -ne 0 ]; then
  exit 1
fi
