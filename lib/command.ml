type command =
  | Check
  | Fmt
  | Plan
  | Diff
  | Apply
  | Confirm
  | Rollback
  | Explain
  | Test
  | Table
  | State
  | Rules
  | History
  | Man
  | Tools
  | Sysctl
  | Completion
  | Version
  | Help

type command_doc = {
  command : command;
  section : int;
  synopsis : string;
  description : string list;
  options : (string * string) list;
  examples : string list;
  files : string list;
  safety_notes : string list;
  see_also : string list;
}

let version = "0.2.1"

let all_commands =
  [
    ("check", Check, "parse and validate policy without touching the host");
    ("fmt", Fmt, "format policy files deterministically");
    ("plan", Plan, "compile policy to a typed backend change plan");
    ("diff", Diff, "show the delta between current host state and a plan");
    ("apply", Apply, "apply a plan with confirmation and rollback support");
    ("confirm", Confirm, "confirm a pending guarded apply");
    ("rollback", Rollback, "restore a previous known-good policy state");
    ("explain", Explain, "explain why a hypothetical packet passes or drops");
    ("test", Test, "run policy assertion fixtures");
    ("table", Table, "manage dynamic policy tables");
    ("state", State, "inspect or modify conntrack state");
    ("rules", Rules, "show or diff generated backend rules");
    ("history", History, "show policy apply history and rollback points");
    ("man", Man, "generate, check, or install man pages");
    ("tools", Tools, "emit tool-calling schemas for AI agents");
    ("sysctl", Sysctl, "check or diff kernel sysctl parameters");
    ("completion", Completion, "emit shell completion script");
    ("version", Version, "print lpf version");
    ("help", Help, "print general or command-specific help");
  ]

let command_name = function
  | Check -> "check"
  | Fmt -> "fmt"
  | Plan -> "plan"
  | Diff -> "diff"
  | Apply -> "apply"
  | Confirm -> "confirm"
  | Rollback -> "rollback"
  | Explain -> "explain"
  | Test -> "test"
  | Table -> "table"
  | State -> "state"
  | Rules -> "rules"
  | History -> "history"
  | Man -> "man"
  | Tools -> "tools"
  | Sysctl -> "sysctl"
  | Completion -> "completion"
  | Version -> "version"
  | Help -> "help"

let command_of_string name =
  all_commands
  |> List.find_opt (fun (candidate, _, _) -> String.equal candidate name)
  |> Option.map (fun (_, command, _) -> command)

let command_summary command =
  all_commands
  |> List.find_opt (fun (_, candidate, _) -> candidate = command)
  |> Option.map (fun (_, _, summary) -> summary)
  |> Option.value ~default:"unknown command"

let shared_files = [ "/etc/lpf.conf"; "/var/lib/lpf/history"; "/var/lib/lpf/rollback" ]

let shared_safety_notes =
  [
    "Run lpf check and lpf plan before applying host changes.";
    "Use guarded apply with an explicit confirmation window for remote hosts.";
    "Keep rollback evidence server-side; never rely on browser-only state.";
  ]


let command_docs =
  [
    {
      command = Check;
      section = 8;
      synopsis = "lpf check [--json] <policy>";
      description =
        [
          "Parse, type-check, validate, and lower an lpf policy into the typed intermediate representation without changing host state.";
          "Diagnostics must include source locations, shadowed-rule warnings, and actionable recovery guidance.";
        ];
      options = [ ("--json", "emit machine-readable validation status and diagnostics") ];
      examples =
        [
          "lpf check /etc/lpf.conf";
          "lpf check --json fixtures/policies/basic.lpf";
        ];
      files = [ "/etc/lpf.conf" ];
      safety_notes = [ "This command is read-only." ];
      see_also = [ "lpf-plan(8)"; "lpf-fmt(8)"; "lpf.conf(5)" ];
    };
    {
      command = Fmt;
      section = 8;
      synopsis = "lpf fmt [--check] [--json] <policy>";
      description = [ "Format policy files deterministically for review and CI." ];
      options =
        [
          ("--check", "fail when formatting would change the policy");
          ("--json", "emit machine-readable formatted text or diagnostics");
        ];
      examples =
        [
          "lpf fmt /etc/lpf.conf";
          "lpf fmt --check /etc/lpf.conf";
          "lpf fmt --json fixtures/policies/basic.lpf";
        ];
      files = [ "/etc/lpf.conf" ];
      safety_notes = [ "Formatting must not change policy semantics." ];
      see_also = [ "lpf-check(8)"; "lpf.conf(5)" ];
    };
    {
      command = Plan;
      section = 8;
      synopsis = "lpf plan [--json] [--backend nftables|tc|routing] <policy>";
      description =
        [
          "Lower policy into a versioned, backend-neutral semantic JSON plan.";
          "Backend plans cover nftables table/chain/set/rule generation, policy routing with ip rule/route tables, tc qdisc/class/shaping compilation, and conntrack declarations.";
        ];
      options =
        [
          ("--json", "emit machine-readable plan output");
          ("--backend nftables|tc|routing", "compile a backend-specific plan");
        ];
      examples =
        [
          "lpf plan /etc/lpf.conf";
          "lpf plan --json /etc/lpf.conf";
          "lpf plan --backend tc /etc/lpf.conf";
          "lpf plan --backend routing /etc/lpf.conf";
        ];
      files = shared_files;
      safety_notes = [ "Planning is read-only but may inspect current host capabilities." ];
      see_also = [ "lpf-diff(8)"; "lpf-apply(8)" ];
    };
    {
      command = Diff;
      section = 8;
      synopsis = "lpf diff [--backend nftables|tc|routing] [--observed <path>|--live] [--json] <policy>";
      description =
        [
          "Compare a generated plan with current lpf-owned host state across backends.";
          "nftables backend: reads live state by default, extracts lpf-owned table blocks, and diffs them against rendered intent.";
          "tc backend: reads qdisc/class state per device and performs semantic comparison against compiled plans.";
          "routing backend: reads ip rule and ip route state and performs semantic comparison.";
          "Supplying --observed reads raw state text from a file or stdin for deterministic tests.";
        ];
      options =
        [
          ("--backend nftables", "select nftables diffing; this is the default");
          ("--backend tc", "select traffic-control qdisc/class diffing");
          ("--backend routing", "select policy-routing rule and route-table diffing");
          ("--observed <path>", "read observed backend text from a file or - for stdin");
          ("--live", "read observed backend state from the host; this is the default");
          ("--json", "emit machine-readable diff status");
        ];
      examples =
        [
          "lpf diff /etc/lpf.conf";
          "lpf diff --observed current.nft fixtures/policies/basic.lpf";
          "lpf diff --backend tc --live fixtures/policies/queue.lpf";
          "lpf diff --backend routing --live fixtures/policies/route-to.lpf";
          "lpf diff --json /etc/lpf.conf";
        ];
      files = shared_files;
      safety_notes = [ "This command is read-only." ];
      see_also = [ "lpf-plan(8)"; "lpf-rules(8)" ];
    };
    {
      command = Apply;
      section = 8;
      synopsis = "lpf apply <policy> [--confirm <duration>]";
      description =
        [
          "Apply a checked policy using the typed backend plan.";
          "Guarded apply records rollback preimages and automatically rolls back if not confirmed.";
        ];
      options =
        [
          ("--confirm <duration>", "require confirmation before the duration expires");
          ("--dry-run", "validate and plan without changing host state");
        ];
      examples = [ "lpf apply /etc/lpf.conf --confirm 60s"; "lpf apply /etc/lpf.conf --dry-run" ];
      files = shared_files;
      safety_notes = shared_safety_notes;
      see_also = [ "lpf-confirm(8)"; "lpf-rollback(8)"; "lpf-history(8)" ];
    };
    {
      command = Confirm;
      section = 8;
      synopsis = "lpf confirm";
      description = [ "Confirm a pending guarded apply and promote it to known-good state." ];
      options = [];
      examples = [ "lpf confirm" ];
      files = shared_files;
      safety_notes = [ "Confirm only after verifying management access and expected traffic behavior." ];
      see_also = [ "lpf-apply(8)"; "lpf-rollback(8)" ];
    };
    {
      command = Rollback;
      section = 8;
      synopsis = "lpf rollback [policy-id]";
      description = [ "Restore a previous lpf policy state and backend preimages." ];
      options = [ ("--now", "rollback the active guarded apply immediately") ];
      examples = [ "lpf rollback"; "lpf rollback 2026-06-16T20:30:00Z" ];
      files = shared_files;
      safety_notes = [ "Rollback must cover nftables, routes, tc, dynamic tables, and owned sysctls." ];
      see_also = [ "lpf-apply(8)"; "lpf-history(8)" ];
    };
    {
      command = Explain;
      section = 8;
      synopsis = "lpf explain [--json] [in|on <iface>] [from <addr>] [to <addr>] [proto <proto>] [port <port>] <policy>";
      description =
        [
          "Explain how a hypothetical packet would be handled by the policy.";
          "The static evaluator simulates matching across rules, NAT, and redirect sections.";
        ];
      options =
        [
          ("--json", "emit machine-readable explanation JSON");
          ("in|on <iface>", "hypothetical ingress interface (default: eth0)");
          ("from <addr>", "hypothetical source address (default: 0.0.0.0)");
          ("to <addr>", "hypothetical destination address (default: 0.0.0.0)");
          ("proto <proto>", "hypothetical protocol (default: any)");
          ("port <port>", "hypothetical destination port");
        ];
      examples =
        [
          "lpf explain from 10.0.0.5 to 1.1.1.1 proto tcp port 443 /etc/lpf.conf";
          "lpf explain in wan from 203.0.113.10 to firewall port 22 /etc/lpf.conf";
          "lpf explain --json from 10.0.0.5 to 1.1.1.1 proto tcp port 443 /etc/lpf.conf";
        ];
      files = shared_files;
      safety_notes = [ "This command is read-only and does not inspect host state." ];
      see_also = [ "lpf-check(8)"; "lpf.conf(5)" ];
    };
    {
      command = Test;
      section = 8;
      synopsis = "lpf test <fixture>";
      description = [ "Run policy assertions covering decisions, NAT, route, queue, log, and tables." ];
      options = [ ("--junit <path>", "write JUnit-compatible test output") ];
      examples = [ "lpf test fixtures/tests/basic.yaml" ];
      files = [ "lpf-policy-tests(5)" ];
      safety_notes = [ "Policy tests must run before guarded apply in CI workflows." ];
      see_also = [ "lpf-explain(8)"; "lpf-policy-tests(5)" ];
    };
    {
      command = Table;
      section = 8;
      synopsis = "lpf table [--json] <name> <add|delete|replace|flush|counters>";
      description = [ "Manage dynamic policy tables without a full policy reload." ];
      options =
        [
          ("--json", "emit machine-readable table element and counter data");
          ("--ttl <duration>", "attach a time-to-live where supported");
        ];
      examples =
        [
          "lpf table threats add 203.0.113.10";
          "lpf table threats counters --json";
          "lpf table threats replace threats.txt";
          "lpf table threats flush";
        ];
      files = shared_files;
      safety_notes = [ "Replacement must be atomic and reversible." ];
      see_also = [ "lpf-plan(8)"; "lpf-rules(8)" ];
    };
    {
      command = State;
      section = 8;
      synopsis = "lpf state [--json] <list|flush|kill>";
      description = [ "Inspect and manage lpf-related conntrack state." ];
      options =
        [
          ("--json", "emit machine-readable state output");
          ("--src <addr>", "source address for kill operation");
          ("--dst <addr>", "destination address for kill operation");
        ];
      examples =
        [
          "lpf state list --json";
          "lpf state kill --src 10.0.0.1 --dst 10.0.0.2";
          "lpf state flush";
        ];
      files = [ "/proc/net/nf_conntrack"; "/var/lib/lpf/history" ];
      safety_notes = [ "Killing conntrack entries can interrupt active connections." ];
      see_also = [ "lpf-rules(8)"; "lpf-history(8)" ];
    };
    {
      command = Rules;
      section = 8;
      synopsis =
        "lpf rules show <policy>\n\
         lpf rules diff --observed <ruleset> <policy>\n\
         lpf rules diff --live <policy>";
      description =
        [
          "Render deterministic read-only nftables rules from a checked lpf policy.";
          "Diff rendered rules against observed lpf-owned nftables table blocks.";
          "Observed rules can be supplied from a file/stdin or read live with `nft list ruleset`.";
          "This command does not apply host changes.";
        ];
      options =
        [
          ("--backend nftables", "select nftables rendering; currently the only backend");
          ("--observed <ruleset>", "read observed nftables ruleset text from a file or - for stdin");
          ("--live", "read observed nftables ruleset text with `nft list ruleset`");
        ];
      examples =
        [
          "lpf rules show fixtures/policies/basic.lpf";
          "lpf rules diff --observed current.nft fixtures/policies/basic.lpf";
          "lpf rules diff --live /etc/lpf.conf";
        ];
      files = shared_files;
      safety_notes = [ "This command is read-only." ];
      see_also = [ "lpf-diff(8)"; "lpf-plan(8)" ];
    };
    {
      command = History;
      section = 8;
      synopsis = "lpf history";
      description = [ "Show policy apply history, checksums, tests, operators, and rollback points." ];
      options = [ ("--json", "emit machine-readable history") ];
      examples = [ "lpf history" ];
      files = [ "/var/lib/lpf/history" ];
      safety_notes = [ "History output must redact private host inventory." ];
      see_also = [ "lpf-rollback(8)"; "lpf-man(8)" ];
    };
    {
      command = Man;
      section = 8;
      synopsis = "lpf man <generate|check|install>";
      description = [ "Generate, check, or install man pages from OCaml command metadata." ];
      options =
        [
          ("--dir <path>", "select generated man page directory for generate/check");
          ("--prefix <path>", "install pages under the prefix share/man tree");
        ];
      examples = [ "lpf man generate"; "lpf man check"; "lpf man install --prefix /usr/local" ];
      files = [ "man/generated"; "/usr/local/share/man" ];
      safety_notes = [ "Generated man pages must be committed with command behavior changes." ];
      see_also = [ "lpf(8)"; "lpf.conf(5)" ];
    };
    {
      command = Tools;
      section = 8;
      synopsis = "lpf tools [--format openai|jsonschema|system-prompt]";
      description =
        [
          "Emit JSON tool-calling schemas for automation agents that need to call lpf commands.";
          "The output is generated from the same OCaml command metadata used for help text and man pages.";
        ];
      options =
        [
          ("--format openai", "emit OpenAI-style tool schema objects; this is the default");
          ("--format jsonschema", "emit standalone JSON Schema objects");
          ("--format system-prompt", "emit a JSON string containing a compact lpf automation prompt");
        ];
      examples = [ "lpf tools"; "lpf tools --format jsonschema"; "lpf tools --format system-prompt" ];
      files = [];
      safety_notes = [ "This command is read-only and must not include host inventory or credentials." ];
      see_also = [ "lpf-man(8)"; "lpf-check(8)" ];
    };
    {
      command = Sysctl;
      section = 8;
      synopsis = "lpf sysctl <check|diff|apply>";
      description =
        [
          "Check, diff, or apply kernel sysctl parameters required by lpf.";
          "check mode reads required sysctls from /proc/sys and prints key=value pairs.";
          "diff mode snapshots observed sysctls and diffs them against the required set.";
          "apply mode writes required sysctls that are not already set to 1.";
        ];
      options = [];
      examples = [ "lpf sysctl check"; "lpf sysctl diff"; "lpf sysctl apply" ];
      files = [ "/proc/sys" ];
      safety_notes = [ "This command is read-only." ];
      see_also = [ "lpf-apply(8)"; "sysctl(8)" ];
    };
    {
      command = Completion;
      section = 8;
      synopsis = "lpf completion [bash]";
      description = [ "Emit the bundled bash completion script." ];
      options = [];
      examples = [ "lpf completion bash" ];
      files = [];
      safety_notes = [];
      see_also = [ "lpf(8)" ];
    };
  ]

let usage_lines () =
  let render (name, _, summary) = Printf.sprintf "  %-15s %s" name summary in
  List.map render all_commands

let help () =
  String.concat "\n"
    ([
       "lpf " ^ version;
       "";
       "Usage:";
       "  lpf <command> [arguments]";
       "";
       "Commands:";
     ]
    @ usage_lines ()
    @ [
        "";
        "Read-only flows (check, fmt, plan, diff, explain, rules, man, tools, sysctl, completion) are implemented. Host mutation (apply, rollback, table, state) and per-backend rollback (nftables, tc, routing) are supported.";
      ])

let command_status = function
  | Check | Fmt | Plan | Diff | Apply | Confirm | Rollback | Explain | Test | Table | State | Rules
  | History | Man | Tools | Sysctl | Completion ->
      "implemented"
  | Version | Help -> "implemented"

let command_help command =
  Printf.sprintf "lpf %s\n\n%s\n\nStatus: %s." (command_name command)
    (command_summary command) (command_status command)
