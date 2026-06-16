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
    ("rules", Rules, "show generated or installed backend rules");
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

let command_help command =
  Printf.sprintf "lpf %s\n\n%s\n\nStatus: planned; implementation must be OCaml."
    (command_name command) (command_summary command)
