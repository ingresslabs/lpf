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

val version : string
val all_commands : (string * command * string) list
val command_name : command -> string
val command_of_string : string -> command option
val command_summary : command -> string
val help : unit -> string
val command_help : command -> string
