let var_dir = try Sys.getenv "LPF_VAR_DIR" with _ -> "/var/lib/lpf"
let rollback_dir = Filename.concat var_dir "rollback"
let preimage_for_id id = Filename.concat rollback_dir ("preimage.nft." ^ id)
let preimage_path = Filename.concat rollback_dir "preimage.nft"
let preimage_tc_path = Filename.concat rollback_dir "preimage.tc"
let preimage_routing_path = Filename.concat rollback_dir "preimage.routing"
let watchdog_pid_path = Filename.concat rollback_dir "watchdog.pid"

let ensure_rollback_dir () =
  if not (Sys.file_exists rollback_dir) then (
    try Unix.mkdir rollback_dir 0o755
    with Unix.Unix_error (error, _, _) ->
      prerr_endline ("warning: could not create rollback directory: " ^ Unix.error_message error))

let write_file path content =
  let out = open_out path in
  Fun.protect ~finally:(fun () -> close_out out) (fun () -> output_string out content)

let parse_duration text =
  if String.length text < 2 then None
  else
    let value_text = String.sub text 0 (String.length text - 1) in
    let unit_char = text.[String.length text - 1] in
    match int_of_string_opt value_text with
    | None -> None
    | Some value -> (
        match unit_char with
        | 's' -> Some value
        | 'm' -> Some (value * 60)
        | 'h' -> Some (value * 3600)
        | _ -> None)

let error_diagnostic ?file message =
  {
    Policy.severity = Diag_error;
    span = { file; line = 1; column = 1; end_column = 1 };
    message;
  }

type runners = {
  list_ruleset : unit -> (string, Nft.run_error) result;
  apply : string -> (unit, Nft.run_error) result;
}

let default_runners = {
  list_ruleset = Nft.list_ruleset;
  apply = Nft.apply;
}

let rollback_now_with_runner runner () =
  if not (Sys.file_exists preimage_path) then Error [ error_diagnostic "no preimage found" ]
  else
    let preimage =
      let ic = open_in preimage_path in
      Fun.protect ~finally:(fun () -> close_in ic) (fun () -> really_input_string ic (in_channel_length ic))
    in
    match runner preimage with
    | Ok () ->
        Sys.remove preimage_path;
        if Sys.file_exists watchdog_pid_path then Sys.remove watchdog_pid_path;
        Ok ((), [])
    | Error error -> Error [ error_diagnostic (Nft.string_of_run_error error) ]

let rollback_now = rollback_now_with_runner default_runners.apply

let confirm () =
  if not (Sys.file_exists watchdog_pid_path) then
    Error [ error_diagnostic "no pending guarded apply found" ]
  else
    let pid_text =
      let ic = open_in watchdog_pid_path in
      Fun.protect ~finally:(fun () -> close_in ic) (fun () -> really_input_string ic (in_channel_length ic))
    in
    match int_of_string_opt pid_text with
    | None -> Error [ error_diagnostic "invalid watchdog PID" ]
    | Some pid -> (
        try
          Unix.kill pid Sys.sigterm;
          Sys.remove watchdog_pid_path;
          if Sys.file_exists preimage_path then Sys.remove preimage_path;
          Ok ((), [])
        with Unix.Unix_error (error, _, _) ->
          Error [ error_diagnostic ("could not kill watchdog: " ^ Unix.error_message error) ])

let get_history () =
  match History.load () with
  | Ok h -> Ok (h, [])
  | Error message -> Error [ error_diagnostic message ]

let rollback_by_id_with_runner runner id =
  let path = preimage_for_id id in
  if not (Sys.file_exists path) then Error [ error_diagnostic ("no preimage found for policy " ^ id) ]
  else
    let preimage =
      let ic = open_in path in
      Fun.protect ~finally:(fun () -> close_in ic) (fun () -> really_input_string ic (in_channel_length ic))
    in
    match runner preimage with
    | Ok () ->
        Sys.remove path;
        Ok ((), [])
    | Error error -> Error [ error_diagnostic (Nft.string_of_run_error error) ]

let rollback_by_id id = rollback_by_id_with_runner default_runners.apply id

let apply_policy_text_with_runners runners ?file ?confirm text =
  match Pipeline.render_nftables_policy_text ?file text with
  | Error diagnostics -> Error diagnostics
  | Ok (rendered, diagnostics) ->
      (match Pipeline.plan_policy_text ?file text with
       | Error e -> Error (diagnostics @ e)
       | Ok (plan, _) ->
          let preimage =
            match confirm with
            | None -> None
          | Some _ -> begin
              match runners.list_ruleset () with
              | Ok ruleset -> Some (Nftables.owned_ruleset_text ruleset)
              | Error _ -> Some ""
            end
          in
          match runners.apply rendered with
          | Error error ->
              Error (diagnostics @ [ error_diagnostic ?file (Nft.string_of_run_error error) ])
          | Ok () ->
              let history_entry = {
            History.id = Digest.to_hex (Digest.string (string_of_float (Unix.gettimeofday ())));
            timestamp = (let tm = Unix.gmtime (Unix.gettimeofday ()) in
                         Printf.sprintf "%04d-%02d-%02dT%02d:%02d:%02dZ"
                           (tm.tm_year + 1900) (tm.tm_mon + 1) tm.tm_mday
                           tm.tm_hour tm.tm_min tm.tm_sec);
            operator = (try Sys.getenv "USER" with _ -> "unknown");
            policy_checksum = plan.Plan.checksum;
            policy_path = Option.value file ~default:"(stdin)";
            test_result = "unknown";
            rollback_available = (confirm <> None);
          } in
          let _ = match History.load () with
            | Ok h -> History.save (History.add history_entry h)
            | Error _ -> History.save [history_entry]
          in
          begin match (confirm, preimage) with
          | None, _ | _, None -> Ok ((), diagnostics)
          | Some duration_text, Some nft_preimage ->
              match parse_duration duration_text with
              | None ->
                  Error (diagnostics @ [ error_diagnostic ?file "invalid confirmation duration" ])
              | Some seconds ->
                  ensure_rollback_dir ();
                  write_file preimage_path nft_preimage;
                  write_file (preimage_for_id history_entry.History.id) nft_preimage;
                  (match Pipeline.render_tc_policy_text ?file text with
                   | Ok (tc_rendered, _) -> write_file preimage_tc_path ("# preimage tc\n" ^ tc_rendered)
                   | _ -> ());
                  (match Pipeline.render_routing_policy_text ?file text with
                   | Ok (routing_rendered, _) -> write_file preimage_routing_path ("# preimage routing\n" ^ routing_rendered)
                   | _ -> ());
                  let lpf_exe = Sys.argv.(0) in
                  let watchdog_command =
                    Printf.sprintf "sleep %d && %s rollback --now" seconds lpf_exe
                  in
                  let pid =
                    Unix.create_process "/bin/sh"
                      [| "/bin/sh"; "-c"; watchdog_command |]
                      Unix.stdin Unix.stdout Unix.stderr
                  in
                  write_file watchdog_pid_path (string_of_int pid);
                  Ok ((), diagnostics)
          end)

let apply_policy_text = apply_policy_text_with_runners default_runners
