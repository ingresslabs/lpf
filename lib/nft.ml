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

let list_ruleset_invocation () = { program = "nft"; argv = [ "nft"; "list"; "ruleset" ] }
let apply_invocation path = { program = "nft"; argv = [ "nft"; "-f"; path ] }

let run invocation = Process.run ~temp_prefix:"lpf-nft" invocation

let list_ruleset_with_runner runner = runner (list_ruleset_invocation ())
let list_ruleset () = list_ruleset_with_runner run

let apply_with_runner runner ruleset =
  Process.with_temp_file "lpf-apply" (fun path ->
      let out = open_out path in
      Fun.protect ~finally:(fun () -> close_out out) (fun () -> output_string out ruleset);
      match runner (apply_invocation path) with
      | Ok _ -> Ok ()
      | Error error -> Error error)

let apply ruleset =
  apply_with_runner run ruleset

let string_of_run_error error = Process.string_of_run_error "nft" error
