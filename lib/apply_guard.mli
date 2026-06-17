type runners = {
  list_ruleset : unit -> (string, Nft.run_error) result;
  apply : string -> (unit, Nft.run_error) result;
}

val default_runners : runners

val var_dir : string
val rollback_dir : string
val preimage_path : string
val watchdog_pid_path : string
val ensure_rollback_dir : unit -> unit
val write_file : string -> string -> unit
val parse_duration : string -> int option
val error_diagnostic : ?file:string -> string -> Policy.diagnostic
val rollback_now : unit -> (unit * Policy.diagnostic list, Policy.diagnostic list) result
val rollback_now_with_runner : (string -> (unit, Nft.run_error) result) -> unit -> (unit * Policy.diagnostic list, Policy.diagnostic list) result
val confirm : unit -> (unit * Policy.diagnostic list, Policy.diagnostic list) result
val get_history : unit -> (History.t * Policy.diagnostic list, Policy.diagnostic list) result
val apply_policy_text :
  ?file:string ->
  ?confirm:string ->
  string ->
  (unit * Policy.diagnostic list, Policy.diagnostic list) result
val apply_policy_text_with_runners :
  runners ->
  ?file:string ->
  ?confirm:string ->
  string ->
  (unit * Policy.diagnostic list, Policy.diagnostic list) result
val rollback_by_id : string -> (unit * Policy.diagnostic list, Policy.diagnostic list) result
val preimage_for_id : string -> string
