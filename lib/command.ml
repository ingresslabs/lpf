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
  | E2e
  | Man
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

let version = "0.1.0-dev"

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
    ("e2e", E2e, "run Firecracker guest end-to-end networking scenarios");
    ("man", Man, "generate, check, or install man pages");
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
  | E2e -> "e2e"
  | Man -> "man"
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
      synopsis = "lpf check <policy>";
      description =
        [
          "Parse, type-check, validate, and lower an lpf policy into the typed intermediate representation without changing host state.";
          "Diagnostics must include source locations, shadowed-rule warnings, and actionable recovery guidance.";
        ];
      options = [];
      examples = [ "lpf check /etc/lpf.conf"; "lpf check fixtures/policies/basic.lpf" ];
      files = [ "/etc/lpf.conf" ];
      safety_notes = [ "This command is read-only." ];
      see_also = [ "lpf-plan(8)"; "lpf-fmt(8)"; "lpf.conf(5)" ];
    };
    {
      command = Fmt;
      section = 8;
      synopsis = "lpf fmt <policy>";
      description = [ "Format policy files deterministically for review and CI." ];
      options = [ ("--check", "fail when formatting would change the policy") ];
      examples = [ "lpf fmt /etc/lpf.conf"; "lpf fmt --check /etc/lpf.conf" ];
      files = [ "/etc/lpf.conf" ];
      safety_notes = [ "Formatting must not change policy semantics." ];
      see_also = [ "lpf-check(8)"; "lpf.conf(5)" ];
    };
    {
      command = Plan;
      section = 8;
      synopsis = "lpf plan [--json] <policy>";
      description =
        [
          "Lower policy into a versioned, backend-neutral semantic JSON plan.";
          "The current Phase 2 plan covers typed policy semantics and stable checksums; later backend phases add nftables, routing, tc, conntrack, logging, sysctl, and rollback preimages.";
        ];
      options = [ ("--json", "emit machine-readable plan output") ];
      examples = [ "lpf plan /etc/lpf.conf"; "lpf plan --json /etc/lpf.conf" ];
      files = shared_files;
      safety_notes = [ "Planning is read-only but may inspect current host capabilities." ];
      see_also = [ "lpf-diff(8)"; "lpf-apply(8)" ];
    };
    {
      command = Diff;
      section = 8;
      synopsis = "lpf diff [--backend nftables] [--observed <ruleset>|--live] [--json] <policy>";
      description =
        [
          "Compare a generated plan with current lpf-owned host state.";
          "The current implementation reads live nftables state by default, extracts lpf-owned table blocks, and compares them with rendered intent.";
          "Supplying --observed reads nftables ruleset text from a file or stdin for deterministic tests.";
        ];
      options =
        [
          ("--backend nftables", "select nftables diffing; currently the only backend");
          ("--observed <ruleset>", "read observed nftables ruleset text from a file or - for stdin");
          ("--live", "read observed nftables ruleset text with `nft list ruleset`; this is the default");
          ("--json", "emit machine-readable nftables diff status and text");
        ];
      examples =
        [
          "lpf diff /etc/lpf.conf";
          "lpf diff --observed current.nft fixtures/policies/basic.lpf";
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
      synopsis = "lpf table <name> <add|delete|replace|show|flush|counters>";
      description = [ "Manage dynamic policy tables without a full policy reload." ];
      options = [ ("--ttl <duration>", "attach a time-to-live where supported") ];
      examples = [ "lpf table threats add 203.0.113.10"; "lpf table threats replace threats.txt" ];
      files = shared_files;
      safety_notes = [ "Replacement must be atomic and reversible." ];
      see_also = [ "lpf-plan(8)"; "lpf-rules(8)" ];
    };
    {
      command = State;
      section = 8;
      synopsis = "lpf state <list|show|flush|kill>";
      description = [ "Inspect and manage lpf-related conntrack state." ];
      options = [ ("--json", "emit machine-readable state output") ];
      examples = [ "lpf state list"; "lpf state kill --src 10.0.0.1 --dst 10.0.0.2" ];
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
      command = E2e;
      section = 8;
      synopsis =
        "lpf e2e run [--scenario-count <n>] [--junit <path>] [--allure-dir <dir>] [--evidence-dir <dir>] [--kernel-id <id>]";
      description =
        [
          "Run real end-to-end Linux networking scenarios intended for Firecracker guest validation.";
          "The runner creates isolated network namespaces, veth links, nftables rules, policy routing entries, tc HTB shaping state, and conntrack evidence.";
          "The default catalog contains 550 deterministic scenarios and supports up to 1000 scenarios across nftables IPv4/IPv6 accept/drop/logging, policy routing, traffic shaping, conntrack, cleanup, readback, and negative-update families.";
        ];
      options =
        [
          ("--scenario-count <n>", "number of scenarios to run; must be between 1 and 1000, default 550");
          ("--junit <path>", "write JUnit XML for Jenkins trend reporting");
          ("--allure-dir <dir>", "write Allure result JSON files");
          ("--evidence-dir <dir>", "write a sanitized evidence manifest and per-scenario JSONL command log");
          ("--kernel-id <id>", "attach a CI kernel label to reports");
          ("--dry-run", "generate catalog reports without changing networking state");
        ];
      examples =
        [
          "lpf e2e run --scenario-count 550 --junit evidence/junit.xml --allure-dir allure-results";
          "lpf e2e run --scenario-count 990 --junit evidence/junit.xml --allure-dir allure-results --evidence-dir evidence/matrix --kernel-id kernel-7.1";
          "lpf e2e run --dry-run --scenario-count 1000 --evidence-dir evidence/dry-run";
          "lpf e2e list --scenario-count 12";
        ];
      files = [ "/run/netns"; "/var/lib/lpf/e2e"; "allure-results"; "evidence/junit.xml"; "evidence/scenario-log.jsonl" ];
      safety_notes =
        [
          "Run inside an isolated Firecracker VM or disposable lab host.";
          "The runner requires root and CAP_NET_ADMIN.";
          "Do not run against a production network namespace.";
        ];
      see_also = [ "lpf-test(8)"; "lpf-diff(8)" ];
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
        "Read-only policy, plan, nftables render, diff, and man-page flows are implemented. Host mutation remains planned.";
      ])

let command_status = function
  | Check | Fmt | Plan | Diff | Apply | Confirm | Rollback | Explain | Test | Table | State | Rules
  | History | E2e | Man ->
      "implemented"
  | Version | Help -> "implemented"

let command_help command =
  Printf.sprintf "lpf %s\n\n%s\n\nStatus: %s." (command_name command)
    (command_summary command) (command_status command)
