type runners = {
  list_ruleset : unit -> (string, Nft.run_error) result;
  apply : string -> (unit, Nft.run_error) result;
  apply_tc : string -> (unit, Nft.run_error) result;
  apply_routing : string -> (unit, Nft.run_error) result;
  tc_delete : string -> (unit, Nft.run_error) result;
  routing_flush_table : int -> (unit, Nft.run_error) result;
}

val parse_duration : string -> int option
val error_diagnostic : ?file:string -> string -> Policy.diagnostic

val rollback_now :
  unit -> (unit * Policy.diagnostic list, Policy.diagnostic list) result

val rollback_now_with_runner :
  (string -> (unit, Nft.run_error) result) ->
  (string -> (unit, Nft.run_error) result) ->
  (int -> (unit, Nft.run_error) result) ->
  unit ->
  (unit * Policy.diagnostic list, Policy.diagnostic list) result

val confirm :
  unit -> (unit * Policy.diagnostic list, Policy.diagnostic list) result

val get_history :
  unit -> (History.t * Policy.diagnostic list, Policy.diagnostic list) result

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

val rollback_by_id :
  string -> (unit * Policy.diagnostic list, Policy.diagnostic list) result
