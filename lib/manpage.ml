type man_page = {
  filename : string;
  section : int;
  title : string;
  content : string;
}

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

let command_page (doc : Command.command_doc) =
  let name = "lpf-" ^ Command.command_name doc.command in
  let title = String.uppercase_ascii name in
  let summary = Command.command_summary doc.command in
  let buffer = Buffer.create 1024 in
  Buffer.add_string buffer
    (Printf.sprintf ".TH %s %d \"June 2026\" \"lpf %s\" \"lpf Manual\"\n" title
       doc.section Command.version);
  add_section buffer "NAME" [ name ^ " - " ^ summary ];
  add_section buffer "SYNOPSIS" [ doc.synopsis ];
  add_section buffer "DESCRIPTION" doc.description;
  if doc.options <> [] then (
    Buffer.add_string buffer ".SH OPTIONS\n";
    add_tagged buffer doc.options);
  if doc.examples <> [] then add_section buffer "EXAMPLES" doc.examples;
  if doc.files <> [] then add_section buffer "FILES" doc.files;
  if doc.safety_notes <> [] then
    add_section buffer "SAFETY NOTES" doc.safety_notes;
  add_section buffer "EXIT STATUS"
    [
      "0 on success.";
      "Non-zero when validation, planning, or host operations fail.";
    ];
  if doc.see_also <> [] then
    add_section buffer "SEE ALSO" [ String.concat ", " doc.see_also ];
  {
    filename = name ^ "." ^ string_of_int doc.section;
    section = doc.section;
    title;
    content = Buffer.contents buffer;
  }

let overview_page () =
  let buffer = Buffer.create 2048 in
  Buffer.add_string buffer
    (Printf.sprintf ".TH LPF 8 \"June 2026\" \"lpf %s\" \"lpf Manual\"\n"
       Command.version);
  add_section buffer "NAME"
    [ "lpf - PF-style control plane for Linux networking" ];
  add_section buffer "SYNOPSIS" [ "lpf <command> [arguments]" ];
  add_section buffer "DESCRIPTION"
    [
      "lpf is an OCaml-first control plane for readable Linux firewall and \
       routing policy.";
      "It compiles typed policy into nftables, policy routing, tc, conntrack, \
       and logging plans.";
      "Remote-safe apply, rollback, explainability, policy tests, generated \
       man pages, and kernel compatibility validation are core requirements.";
    ];
  Buffer.add_string buffer ".SH COMMANDS\n";
  Command.command_docs
  |> List.iter (fun (doc : Command.command_doc) ->
         add_tagged buffer
           [
             ( "lpf " ^ Command.command_name doc.command,
               Command.command_summary doc.command );
           ]);
  add_section buffer "EXAMPLES"
    [
      "lpf check /etc/lpf.conf";
      "lpf plan --json /etc/lpf.conf";
      "lpf diff --live /etc/lpf.conf";
      "lpf apply /etc/lpf.conf --confirm 60s";
      "lpf explain from 10.0.0.5 to 1.1.1.1 proto tcp port 443 /etc/lpf.conf";
    ];
  add_section buffer "FILES" Command.shared_files;
  add_section buffer "SAFETY NOTES" Command.shared_safety_notes;
  add_section buffer "SEE ALSO"
    [ "lpf.conf(5), lpf-policy-tests(5), lpf-apply(8), lpf-man(8)" ];
  {
    filename = "lpf.8";
    section = 8;
    title = "LPF";
    content = Buffer.contents buffer;
  }

let config_page () =
  let buffer = Buffer.create 1024 in
  Buffer.add_string buffer
    (Printf.sprintf ".TH LPF.CONF 5 \"June 2026\" \"lpf %s\" \"lpf Manual\"\n"
       Command.version);
  add_section buffer "NAME" [ "lpf.conf - lpf policy file format" ];
  add_section buffer "DESCRIPTION"
    [
      "The lpf policy format is a PF-inspired language for Linux networking.";
      "The current parser covers default actions, interfaces, macros, tables, \
       queues, anchors, pass/block rules, rule logging, NAT, redirects, and \
       rule-level route-to annotations.";
      "Checked policies are lowered into a typed intermediate representation \
       before backend planning.";
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
      "pass out log on wan proto tcp from any to any port 443 queue std \
       route-to 1.1.1.1 (wan) keep state";
      "block in log (all) on wan proto icmp from any to any";
    ];
  add_section buffer "SEE ALSO" [ "lpf-check(8), lpf-plan(8), lpf-apply(8)" ];
  {
    filename = "lpf.conf.5";
    section = 5;
    title = "LPF.CONF";
    content = Buffer.contents buffer;
  }

let policy_tests_page () =
  let buffer = Buffer.create 1024 in
  Buffer.add_string buffer
    (Printf.sprintf
       ".TH LPF-POLICY-TESTS 5 \"June 2026\" \"lpf %s\" \"lpf Manual\"\n"
       Command.version);
  add_section buffer "NAME"
    [ "lpf-policy-tests - policy assertion fixture format" ];
  add_section buffer "DESCRIPTION"
    [
      "Policy tests describe expected pass, drop, reject, NAT, route, queue, \
       log, and table behavior.";
      "The fixture format is planned as an OCaml-validated schema used by lpf \
       test and CI.";
    ];
  add_section buffer "EXAMPLES"
    [
      "from: 10.0.0.5"; "to: 1.1.1.1"; "proto: tcp"; "port: 443"; "expect: pass";
    ];
  add_section buffer "SEE ALSO" [ "lpf-test(8), lpf-explain(8)" ];
  {
    filename = "lpf-policy-tests.5";
    section = 5;
    title = "LPF-POLICY-TESTS";
    content = Buffer.contents buffer;
  }

let man_pages () =
  (overview_page () :: List.map command_page Command.command_docs)
  @ [ config_page (); policy_tests_page () ]

let man_page_content page = page.content
