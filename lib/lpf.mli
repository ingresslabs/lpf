type command = Command.command =
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
  | Support_bundle
  | E2e
  | Man
  | Version
  | Help

type command_doc = Command.command_doc = {
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

type man_page = Manpage.man_page = {
  filename : string;
  section : int;
  title : string;
  content : string;
}

module Policy : module type of Policy
module Ir : module type of Ir
module Plan : module type of Plan
module Nftables : module type of Nftables
module Tc : module type of Tc
module Routing : module type of Routing
module Nft : module type of Nft
module Explain : module type of Explain
module Json_util : module type of Json_util
module Test_engine : module type of Test_engine
module Test_parser : module type of Test_parser
module History : module type of History
module Apply_guard : module type of Apply_guard
module Conntrack : module type of Conntrack
module Table : module type of Table
module E2e : module type of E2e

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
val plan_of_policy : Policy.policy -> (Plan.t, Policy.diagnostic list) result
val plan_policy_text :
  ?file:string -> string -> (Plan.t * Policy.diagnostic list, Policy.diagnostic list) result
val render_nftables_policy_text :
  ?file:string -> string -> (string * Policy.diagnostic list, Policy.diagnostic list) result
val render_tc_policy_text :
  ?file:string -> string -> (string * Policy.diagnostic list, Policy.diagnostic list) result
val render_routing_policy_text :
  ?file:string -> string -> (string * Policy.diagnostic list, Policy.diagnostic list) result
val diff_nftables_policy_text :
  ?file:string ->
  observed:string ->
  string ->
  (string * Policy.diagnostic list, Policy.diagnostic list) result
val diff_nftables_policy :
  ?file:string ->
  observed:string ->
  string ->
  (Nftables.diff_result * Policy.diagnostic list, Policy.diagnostic list) result
val explain_policy_text :
  ?file:string ->
  packet:Explain.packet ->
  string ->
  (Explain.explanation * Policy.diagnostic list, Policy.diagnostic list) result
val run_policy_tests :
  ?file:string ->
  string ->
  ((Test_engine.test_case * Test_engine.test_result list) list * Policy.diagnostic list,
   Policy.diagnostic list) result
val apply_policy_text :
  ?file:string ->
  ?confirm:string ->
  string ->
  (unit * Policy.diagnostic list, Policy.diagnostic list) result
val confirm : unit -> (unit * Policy.diagnostic list, Policy.diagnostic list) result
val rollback_now : unit -> (unit * Policy.diagnostic list, Policy.diagnostic list) result
val get_history : unit -> (History.t * Policy.diagnostic list, Policy.diagnostic list) result
