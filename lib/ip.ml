type invocation = Process.invocation = {
  program : string;
  argv : string list;
}

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

let rule_list_invocation () = { program = "ip"; argv = [ "ip"; "rule"; "list" ] }
let route_show_invocation () = { program = "ip"; argv = [ "ip"; "route"; "show"; "table"; "all" ] }

let run invocation = Process.run ~temp_prefix:"lpf-ip" invocation

let rule_list_with_runner runner = runner (rule_list_invocation ())
let rule_list () = rule_list_with_runner run

let route_show_with_runner runner = runner (route_show_invocation ())
let route_show () = route_show_with_runner run

let string_of_run_error error = Process.string_of_run_error "ip" error
