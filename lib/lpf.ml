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
  | Import
  | Ui
  | Support_bundle
  | Kernel_matrix
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

type man_page = {
  filename : string;
  section : int;
  title : string;
  content : string;
}

module Policy = Policy
module Ir = Ir
module Plan = Plan

let ir_of_policy = Ir.of_policy

let plan_of_policy policy =
  match Ir.of_policy policy with
  | Ok ir -> Ok (Plan.of_ir ir)
  | Error diagnostics -> Error diagnostics

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
    ("import", Import, "import existing nftables or iptables-save policy");
    ("ui", Ui, "serve, build, or test the Bonsai browser UI");
    ("support-bundle", Support_bundle, "collect redacted diagnostic evidence");
    ("kernel-matrix", Kernel_matrix, "run or plan latest-kernel validation");
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
  | Import -> "import"
  | Ui -> "ui"
  | Support_bundle -> "support-bundle"
  | Kernel_matrix -> "kernel-matrix"
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
      synopsis = "lpf diff <policy>";
      description = [ "Compare a generated plan with current lpf-owned host state." ];
      options = [ ("--json", "emit semantic diff as machine-readable output") ];
      examples = [ "lpf diff /etc/lpf.conf" ];
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
      synopsis = "lpf explain from <addr> to <addr> proto <proto> port <port>";
      description =
        [
          "Explain how a hypothetical packet would be handled by policy.";
          "Results include decision, policy rule, NAT, route, queue, log, and state behavior.";
        ];
      options = [ ("--json", "emit machine-readable explanation") ];
      examples = [ "lpf explain from 10.0.0.5 to 1.1.1.1 proto tcp port 443" ];
      files = [ "/etc/lpf.conf" ];
      safety_notes = [ "Explain is advisory until compared with installed backend state." ];
      see_also = [ "lpf-test(8)"; "lpf-rules(8)" ];
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
      synopsis = "lpf state <list|show|kill|flush-policy>";
      description = [ "Inspect and manage lpf-related conntrack state." ];
      options = [ ("--json", "emit machine-readable state output") ];
      examples = [ "lpf state list"; "lpf state kill --policy-id abc123" ];
      files = [ "/proc/net/nf_conntrack"; "/var/lib/lpf/history" ];
      safety_notes = [ "Killing conntrack entries can interrupt active connections." ];
      see_also = [ "lpf-rules(8)"; "lpf-history(8)" ];
    };
    {
      command = Rules;
      section = 8;
      synopsis =
        "lpf rules show <policy>\n\
         lpf rules diff --observed <ruleset> <policy>";
      description =
        [
          "Render deterministic read-only nftables rules from a checked lpf policy.";
          "Diff rendered rules against observed lpf-owned nftables table blocks.";
          "This command reads supplied observed ruleset text and does not apply host changes.";
        ];
      options =
        [
          ("--backend nftables", "select nftables rendering; currently the only backend");
          ("--observed <ruleset>", "read observed nftables ruleset text from a file or - for stdin");
        ];
      examples =
        [
          "lpf rules show fixtures/policies/basic.lpf";
          "lpf rules diff --observed current.nft fixtures/policies/basic.lpf";
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
      see_also = [ "lpf-rollback(8)"; "lpf-support-bundle(8)" ];
    };
    {
      command = Import;
      section = 8;
      synopsis = "lpf import <nftables|iptables-save|ufw|firewalld>";
      description = [ "Import existing firewall state into an lpf policy starting point." ];
      options = [ ("--output <path>", "write imported policy to a file") ];
      examples = [ "lpf import nftables"; "lpf import iptables-save < rules.v4" ];
      files = [ "/etc/nftables.conf"; "/etc/ufw"; "/etc/firewalld" ];
      safety_notes = [ "Untranslatable constructs must be marked explicitly and never silently dropped." ];
      see_also = [ "lpf-check(8)"; "lpf.conf(5)" ];
    };
    {
      command = Ui;
      section = 8;
      synopsis = "lpf ui <serve|build|test>";
      description =
        [
          "Serve, build, or test the Bonsai/Bonsai_web browser UI.";
          "The browser UI uses typed OCaml API endpoints and never executes host commands directly.";
        ];
      options = [ ("--mock", "serve UI with mock API responses"); ("--listen <addr:port>", "bind UI server address") ];
      examples = [ "lpf ui serve --mock"; "lpf ui serve --listen 127.0.0.1:9443" ];
      files = [ "/var/lib/lpf/ui-session"; "/var/lib/lpf/history" ];
      safety_notes =
        [
          "Bind to localhost by default.";
          "Require plan checksum confirmation for destructive actions.";
          "Keep rollback preimages server-side.";
        ];
      see_also = [ "lpf-apply(8)"; "lpf-explain(8)"; "lpf-support-bundle(8)" ];
    };
    {
      command = Support_bundle;
      section = 8;
      synopsis = "lpf support-bundle";
      description = [ "Collect redacted diagnostic evidence for support and release validation." ];
      options = [ ("--output <path>", "write the bundle to a target directory or archive") ];
      examples = [ "lpf support-bundle --output /tmp/lpf-support" ];
      files = shared_files;
      safety_notes = [ "Never include raw secrets, private keys, packet payloads, or unredacted inventory." ];
      see_also = [ "lpf-history(8)"; "lpf-kernel-matrix(8)" ];
    };
    {
      command = Kernel_matrix;
      section = 8;
      synopsis = "lpf kernel-matrix <plan|run>";
      description = [ "Plan or run latest-five kernel compatibility validation." ];
      options = [ ("--lab <id>", "select a lab profile such as 141") ];
      examples = [ "lpf kernel-matrix plan"; "lpf kernel-matrix run --lab 141" ];
      files = [ "/var/lib/lpf/kernel-matrix" ];
      safety_notes = [ "Do not commit raw lab logs, credentials, private inventories, or secret material." ];
      see_also = [ "lpf-support-bundle(8)" ];
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

let roff_escape text =
  let buffer = Buffer.create (String.length text) in
  String.iter
    (function
      | '\\' -> Buffer.add_string buffer "\\e"
      | '-' -> Buffer.add_string buffer "\\-"
      | c -> Buffer.add_char buffer c)
    text;
  Buffer.contents buffer

let roff_line text =
  let escaped = roff_escape text in
  if String.length escaped > 0 && (escaped.[0] = '.' || escaped.[0] = '\'') then
    "\\&" ^ escaped
  else escaped

let add_section buffer name lines =
  Buffer.add_string buffer (".SH " ^ name ^ "\n");
  List.iter (fun line -> Buffer.add_string buffer (roff_line line ^ "\n")) lines

let add_tagged buffer entries =
  List.iter
    (fun (tag, body) ->
      Buffer.add_string buffer ".TP\n";
      Buffer.add_string buffer (roff_line tag ^ "\n");
      Buffer.add_string buffer (roff_line body ^ "\n"))
    entries

let command_page doc =
  let name = "lpf-" ^ command_name doc.command in
  let title = String.uppercase_ascii name in
  let summary = command_summary doc.command in
  let buffer = Buffer.create 1024 in
  Buffer.add_string buffer
    (Printf.sprintf ".TH %s %d \"June 2026\" \"lpf %s\" \"lpf Manual\"\n"
       title doc.section version);
  add_section buffer "NAME" [ name ^ " - " ^ summary ];
  add_section buffer "SYNOPSIS" [ doc.synopsis ];
  add_section buffer "DESCRIPTION" doc.description;
  if doc.options <> [] then (
    Buffer.add_string buffer ".SH OPTIONS\n";
    add_tagged buffer doc.options);
  if doc.examples <> [] then add_section buffer "EXAMPLES" doc.examples;
  if doc.files <> [] then add_section buffer "FILES" doc.files;
  if doc.safety_notes <> [] then add_section buffer "SAFETY NOTES" doc.safety_notes;
  add_section buffer "EXIT STATUS" [ "0 on success."; "Non-zero when validation, planning, or host operations fail." ];
  if doc.see_also <> [] then add_section buffer "SEE ALSO" [ String.concat ", " doc.see_also ];
  {
    filename = name ^ "." ^ string_of_int doc.section;
    section = doc.section;
    title;
    content = Buffer.contents buffer;
  }

let overview_page () =
  let buffer = Buffer.create 2048 in
  Buffer.add_string buffer
    (Printf.sprintf ".TH LPF 8 \"June 2026\" \"lpf %s\" \"lpf Manual\"\n" version);
  add_section buffer "NAME" [ "lpf - PF-style control plane for Linux networking" ];
  add_section buffer "SYNOPSIS" [ "lpf <command> [arguments]" ];
  add_section buffer "DESCRIPTION"
    [
      "lpf is an OCaml-first control plane for readable Linux firewall and routing policy.";
      "It compiles typed policy into nftables, policy routing, tc, conntrack, and logging plans.";
      "Remote-safe apply, rollback, explainability, policy tests, generated man pages, and kernel-matrix validation are core requirements.";
    ];
  Buffer.add_string buffer ".SH COMMANDS\n";
  command_docs
  |> List.iter (fun doc ->
         add_tagged buffer
           [ ("lpf " ^ command_name doc.command, command_summary doc.command) ]);
  add_section buffer "FILES" shared_files;
  add_section buffer "SAFETY NOTES" shared_safety_notes;
  add_section buffer "SEE ALSO" [ "lpf.conf(5), lpf-policy-tests(5), lpf-apply(8), lpf-man(8)" ];
  { filename = "lpf.8"; section = 8; title = "LPF"; content = Buffer.contents buffer }

let config_page () =
  let buffer = Buffer.create 1024 in
  Buffer.add_string buffer
    (Printf.sprintf ".TH LPF.CONF 5 \"June 2026\" \"lpf %s\" \"lpf Manual\"\n" version);
  add_section buffer "NAME" [ "lpf.conf - lpf policy file format" ];
  add_section buffer "DESCRIPTION"
    [
      "The lpf policy format is a PF-inspired language for Linux networking.";
      "The current parser covers default actions, interfaces, macros, tables, queues, anchors, pass/block rules, rule logging, NAT, redirects, and rule-level route-to annotations.";
      "Checked policies are lowered into a typed intermediate representation before backend planning.";
      "Rule logging supports log, log (all), log (matches), and log (user).";
      "Later phases will add stable JSON plans and backend compilation.";
    ];
  add_section buffer "EXAMPLES"
    [
      "set default deny";
      "interface wan = \"eth0\"";
      "table <trusted> { 10.0.0.0/8, 192.168.0.0/16 }";
      "queue std on wan bandwidth 10M";
      "anchor internal {";
      "  pass in on wan from any to any queue std";
      "}";
      "pass out log on wan proto tcp from any to any port 443 queue std route-to 1.1.1.1 (wan) keep state";
      "block in log (all) on wan proto icmp from any to any";
    ];
  add_section buffer "SEE ALSO" [ "lpf-check(8), lpf-plan(8), lpf-apply(8)" ];
  { filename = "lpf.conf.5"; section = 5; title = "LPF.CONF"; content = Buffer.contents buffer }

let policy_tests_page () =
  let buffer = Buffer.create 1024 in
  Buffer.add_string buffer
    (Printf.sprintf ".TH LPF-POLICY-TESTS 5 \"June 2026\" \"lpf %s\" \"lpf Manual\"\n" version);
  add_section buffer "NAME" [ "lpf-policy-tests - policy assertion fixture format" ];
  add_section buffer "DESCRIPTION"
    [
      "Policy tests describe expected pass, drop, reject, NAT, route, queue, log, and table behavior.";
      "The fixture format is planned as an OCaml-validated schema used by lpf test and CI.";
    ];
  add_section buffer "EXAMPLES"
    [
      "from: 10.0.0.5";
      "to: 1.1.1.1";
      "proto: tcp";
      "port: 443";
      "expect: pass";
    ];
  add_section buffer "SEE ALSO" [ "lpf-test(8), lpf-explain(8)" ];
  { filename = "lpf-policy-tests.5"; section = 5; title = "LPF-POLICY-TESTS"; content = Buffer.contents buffer }

let man_pages () = overview_page () :: List.map command_page command_docs @ [ config_page (); policy_tests_page () ]

let man_page_content page = page.content

let check_policy_text ?file text =
  let result = Policy.check ?file text in
  match result.policy with
  | None -> result
  | Some policy -> (
      match Ir.of_policy policy with
      | Error ir_diags ->
          { Policy.diagnostics = result.diagnostics @ ir_diags; policy = None }
      | Ok ir ->
          let shadow_diags = Ir.shadow_diagnostics ir in
          { Policy.diagnostics = result.diagnostics @ shadow_diags; policy = Some policy })

let format_policy_text ?file text =
  match Policy.check ?file text with
  | { policy = Some policy; diagnostics = _ } -> Ok (Policy.format policy)
  | { policy = None; diagnostics } -> Error diagnostics

let plan_policy_text ?file text =
  let result = check_policy_text ?file text in
  match result.policy with
  | None -> Error result.diagnostics
  | Some policy -> (
      match plan_of_policy policy with
      | Ok plan -> Ok (plan, result.diagnostics)
      | Error diagnostics -> Error (result.diagnostics @ diagnostics))

let render_nftables_policy_text ?file text =
  match plan_policy_text ?file text with
  | Ok (plan, diagnostics) -> Ok (Nftables.render_plan plan, diagnostics)
  | Error diagnostics -> Error diagnostics

let diff_nftables_policy_text ?file ~observed text =
  match render_nftables_policy_text ?file text with
  | Ok (intended, diagnostics) -> Ok (Nftables.diff_text ~intended ~observed, diagnostics)
  | Error diagnostics -> Error diagnostics

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
        "This scaffold exposes the command contract. Backend behavior is not implemented yet.";
      ])

let command_status = function
  | Check | Fmt | Plan | Rules | Man -> "implemented"
  | Version | Help -> "implemented"
  | _ -> "planned; implementation must be OCaml"

let command_help command =
  Printf.sprintf "lpf %s\n\n%s\n\nStatus: %s." (command_name command)
    (command_summary command) (command_status command)
