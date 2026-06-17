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

val run : temp_prefix:string -> invocation -> (string, run_error) result
val string_of_run_status : run_status -> string
val string_of_run_error : string -> run_error -> string

val close_noerr : Unix.file_descr -> unit
val read_file : string -> string
val with_temp_file : string -> (string -> 'a) -> 'a
