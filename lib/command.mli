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
  | Prove
  | Man
  | Tools
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

val version : string
val all_commands : (string * command * string) list
val command_name : command -> string
val command_of_string : string -> command option
val command_summary : command -> string
val command_docs : command_doc list
val shared_files : string list
val shared_safety_notes : string list
val help : unit -> string
val command_help : command -> string
