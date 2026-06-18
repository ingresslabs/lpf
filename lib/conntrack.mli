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

type conntrack_entry = {
  protocol : string;
  src : string;
  dst : string;
  sport : string;
  dport : string;
  state : string;
  raw : string;
}

val list : unit -> (string, run_error) result

val list_with_runner :
  (invocation -> (string, run_error) result) -> (string, run_error) result

val delete :
  src:string ->
  dst:string ->
  ?sport:string ->
  ?dport:string ->
  unit ->
  (unit, run_error) result

val delete_with_runner :
  (invocation -> (string, run_error) result) ->
  src:string ->
  dst:string ->
  ?sport:string ->
  ?dport:string ->
  unit ->
  (unit, run_error) result

val flush : unit -> (unit, run_error) result

val flush_with_runner :
  (invocation -> (string, run_error) result) -> (unit, run_error) result

val string_of_run_error : run_error -> string
val parse_list : string -> conntrack_entry list
val entry_to_json : conntrack_entry -> string
val entries_to_json : conntrack_entry list -> string
