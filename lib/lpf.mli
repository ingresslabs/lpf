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

module Policy : module type of Policy
module Ir : module type of Ir

val version : string
val all_commands : (string * command * string) list
val command_name : command -> string
val command_of_string : string -> command option
val command_summary : command -> string
val command_docs : command_doc list
val help : unit -> string
val command_help : command -> string
val man_pages : unit -> man_page list
val man_page_content : man_page -> string
val check_policy_text : ?file:string -> string -> Policy.check_result
val format_policy_text : ?file:string -> string -> (string, Policy.diagnostic list) result
val ir_of_policy : Policy.policy -> (Ir.t, Policy.diagnostic list) result
