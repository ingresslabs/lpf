let var_dir = try Sys.getenv "LPF_VAR_DIR" with _ -> "/var/lib/lpf"
let rollback_dir = Filename.concat var_dir "rollback"
let preimage_for_id id = Filename.concat rollback_dir ("preimage.nft." ^ id)
let preimage_path = Filename.concat rollback_dir "preimage.nft"
let preimage_tc_path = Filename.concat rollback_dir "preimage.tc"
let preimage_tc_devices_path = Filename.concat rollback_dir "preimage.tc.devices"
let preimage_routing_path = Filename.concat rollback_dir "preimage.routing"
let preimage_routing_tables_path = Filename.concat rollback_dir "preimage.routing.tables"
let watchdog_pid_path = Filename.concat rollback_dir "watchdog.pid"

let ensure_dir = File_util.ensure_dir ~strict:false
let write_file = File_util.write_file

let ensure_rollback_dir () =
  ensure_dir var_dir;
  ensure_dir rollback_dir

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
  tc_delete : string -> (unit, Nft.run_error) result;
  routing_flush_table : int -> (unit, Nft.run_error) result;
}

let default_runners = {
  list_ruleset = Nft.list_ruleset;
  apply = Nft.apply;
  tc_delete = Tc.delete;
  routing_flush_table = (fun table ->
    let invocation = { Process.program = "ip"; argv = [ "ip"; "route"; "flush"; "table"; string_of_int table ] } in
    match Nft.run invocation with
    | Ok _ -> Ok ()
    | Error error -> Error error);
}

let cleanup_rollback_files () =
  let paths = [ preimage_path; preimage_tc_path; preimage_tc_devices_path;
                preimage_routing_path; preimage_routing_tables_path; watchdog_pid_path ] in
  List.iter (fun path -> if Sys.file_exists path then Sys.remove path) paths

let restore_tc runner _path devices_path =
  let devices =
    if Sys.file_exists devices_path then
      let ic = open_in devices_path in
      let content = Fun.protect ~finally:(fun () -> close_in ic)
          (fun () -> really_input_string ic (in_channel_length ic)) in
      String.split_on_char '\n' content |> List.filter (fun s -> String.length s > 0)
    else []
  in
  match devices with
  | [] -> Ok ()
  | _ ->
      let rec loop = function
        | [] -> Ok ()
        | device :: rest ->
            match runner device with
            | Ok () -> loop rest
            | Error error -> Error error
      in
      loop devices

let restore_routing runner tables_path =
  let tables =
    if Sys.file_exists tables_path then
      let ic = open_in tables_path in
      let content = Fun.protect ~finally:(fun () -> close_in ic)
          (fun () -> really_input_string ic (in_channel_length ic)) in
      String.split_on_char '\n' content
      |> List.filter_map (fun s -> int_of_string_opt (String.trim s))
    else []
  in
  match tables with
  | [] -> Ok ()
  | _ ->
      let rec loop = function
        | [] -> Ok ()
        | table :: rest ->
            match runner table with
            | Ok () -> loop rest
            | Error error -> Error error
      in
      loop tables

let rollback_now_with_runner apply_runner tc_runner routing_runner () =
  if not (Sys.file_exists preimage_path) then Error [ error_diagnostic "no preimage found" ]
  else
    let preimage =
      let ic = open_in preimage_path in
      Fun.protect ~finally:(fun () -> close_in ic) (fun () -> really_input_string ic (in_channel_length ic))
    in
    let tc_result = restore_tc tc_runner preimage_tc_path preimage_tc_devices_path in
    let routing_result = restore_routing routing_runner preimage_routing_tables_path in
    match apply_runner preimage with
    | Ok () ->
        cleanup_rollback_files ();
        (match tc_result with
         | Error error -> Error [ error_diagnostic ("tc rollback failed: " ^ Nft.string_of_run_error error) ]
         | Ok () ->
             (match routing_result with
              | Error error -> Error [ error_diagnostic ("routing rollback failed: " ^ Nft.string_of_run_error error) ]
              | Ok () -> Ok ((), [])))
    | Error error ->
        (match tc_result, routing_result with
         | Ok (), Ok () -> ()
         | _ -> ());
        cleanup_rollback_files ();
        Error [ error_diagnostic (Nft.string_of_run_error error) ]

let rollback_now = rollback_now_with_runner default_runners.apply default_runners.tc_delete default_runners.routing_flush_table

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
          cleanup_rollback_files ();
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
                    | Ok (tc_rendered, _) ->
                        write_file preimage_tc_path ("# preimage tc\n" ^ tc_rendered);
                        (match Pipeline.plan_policy_text ?file text with
                         | Ok (plan, _) ->
                             let tc_plan = Tc.compile plan.policy in
                             let devices =
                               List.fold_left (fun acc cmd ->
                                 match cmd with
                                 | Tc.Qdisc_add q -> q.device :: acc
                                 | Tc.Class_add c -> c.device :: acc)
                               [] tc_plan
                               |> List.sort_uniq String.compare
                             in
                             write_file preimage_tc_devices_path (String.concat "\n" devices ^ "\n")
                         | Error _ -> ())
                    | Error _ -> ());
                   (match Pipeline.render_routing_policy_text ?file text with
                    | Ok (routing_rendered, _) ->
                        write_file preimage_routing_path ("# preimage routing\n" ^ routing_rendered);
                        (match Pipeline.plan_policy_text ?file text with
                         | Ok (plan, _) ->
                             let routing_plan = Routing.compile plan.policy in
                             let tables =
                               List.filter_map (fun cmd ->
                                 match cmd with
                                 | Routing.Ip_rule_add r -> Some r.table
                                 | Routing.Ip_route_add_default r -> Some r.table)
                               routing_plan
                               |> List.sort_uniq Int.compare
                             in
                             write_file preimage_routing_tables_path (String.concat "\n" (List.map string_of_int tables) ^ "\n")
                         | Error _ -> ())
                    | Error _ -> ());
                   let lpf_exe =
                     let arg0 = Sys.argv.(0) in
                     if Filename.is_relative arg0 then
                       let cwd = Sys.getcwd () in
                       Filename.concat cwd arg0
                     else arg0
                   in
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
