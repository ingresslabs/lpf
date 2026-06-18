type invocation = Process.invocation = { program : string; argv : string list }

type run_status = Process.run_status =
  | Exited of int
  | Signaled of int
  | Stopped of int
  | Failed_to_start of string

type run_error = Process.run_error = {
  invocation : invocation;
  status : run_status;
  stderr : string;
}

type observed_rule = { priority : int; fwmark : int option; table : int }
type observed_route = { gateway : string; device : string option; table : int }

val rule_list : unit -> (string, run_error) result

val rule_list_with_runner :
  (invocation -> (string, run_error) result) -> (string, run_error) result

val route_show : int -> (string, run_error) result

val route_show_with_runner :
  (invocation -> (string, run_error) result) ->
  int ->
  (string, run_error) result

val string_of_run_error : run_error -> string
val delete_rules : unit -> (unit, run_error) result

val delete_rules_with_runner :
  (invocation -> (string, run_error) result) -> (unit, run_error) result

val flush_table : int -> (unit, run_error) result

val flush_table_with_runner :
  (invocation -> (string, run_error) result) -> int -> (unit, run_error) result

val parse_rule_list : string -> observed_rule list
val parse_route_show : string -> observed_route list
