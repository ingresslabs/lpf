type invocation = {
  program : string;
  argv : string list;
}

type run_status =
  | Exited of int
  | Signaled of int
  | Stopped of int
  | Failed_to_start of string

type run_error = {
  invocation : invocation;
  status : run_status;
  stderr : string;
}

val rule_list : unit -> (string, run_error) result
val rule_list_with_runner : (invocation -> (string, run_error) result) -> (string, run_error) result
val route_show : unit -> (string, run_error) result
val route_show_with_runner : (invocation -> (string, run_error) result) -> (string, run_error) result
val string_of_run_error : run_error -> string
