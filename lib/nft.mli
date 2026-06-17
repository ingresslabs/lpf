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

val list_ruleset_invocation : unit -> invocation
val run : invocation -> (string, run_error) result
val list_ruleset_with_runner : (invocation -> (string, run_error) result) -> (string, run_error) result
val list_ruleset : unit -> (string, run_error) result
val string_of_run_error : run_error -> string
