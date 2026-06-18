let print_end text =
  print_string text;
  print_newline ()

let default_man_dir = "man/generated"
let read_file = Lpf.File_util.read_file
let write_file = Lpf.File_util.write_file
let ensure_dir = Lpf.File_util.ensure_dir
let read_stdin = Lpf.File_util.read_stdin

let generated_path ~dir page = Filename.concat dir page.Lpf.filename

let generate_man_pages ~dir =
  ensure_dir dir;
  Lpf.man_pages ()
  |> List.iter (fun page -> write_file (generated_path ~dir page) (Lpf.man_page_content page));
  Printf.printf "generated %d man pages in %s\n" (List.length (Lpf.man_pages ())) dir

let check_man_pages ~dir =
  let mismatches =
    Lpf.man_pages ()
    |> List.filter_map (fun page ->
           let path = generated_path ~dir page in
           if not (Sys.file_exists path) then Some (path ^ " is missing")
           else
             let actual = read_file path in
             let expected = Lpf.man_page_content page in
             if String.equal actual expected then None else Some (path ^ " is stale"))
  in
  match mismatches with
  | [] ->
      Printf.printf "checked %d man pages in %s\n" (List.length (Lpf.man_pages ())) dir;
      0
  | _ ->
      List.iter prerr_endline mismatches;
      1

let install_man_pages ~prefix =
  Lpf.man_pages ()
  |> List.iter (fun page ->
         let dir =
           Filename.concat
             (Filename.concat (Filename.concat prefix "share") "man")
             ("man" ^ string_of_int page.Lpf.section)
         in
         ensure_dir dir;
         write_file (Filename.concat dir page.Lpf.filename) (Lpf.man_page_content page));
  Printf.printf "installed %d man pages under %s\n" (List.length (Lpf.man_pages ())) prefix

let parse_value_option ~name ~default args =
  let rec loop current = function
    | [] -> current
    | flag :: value :: rest when String.equal flag name -> loop value rest
    | _ :: rest -> loop current rest
  in
  loop default args

let handle_man args =
  match args with
  | "generate" :: rest ->
      let dir = parse_value_option ~name:"--dir" ~default:default_man_dir rest in
      generate_man_pages ~dir
  | "check" :: rest ->
      let dir = parse_value_option ~name:"--dir" ~default:default_man_dir rest in
      exit (check_man_pages ~dir)
  | "install" :: rest ->
      let prefix = parse_value_option ~name:"--prefix" ~default:"/usr/local" rest in
      install_man_pages ~prefix
  | _ ->
      prerr_endline "usage: lpf man <generate|check|install> [--dir DIR] [--prefix PREFIX]";
      exit 64

let exit_for_policy_check result =
  let output = Lpf.Policy.format_check_result result in
  if output <> "" then prerr_endline output;
  match result.Lpf.Policy.policy with
  | Some _ -> exit 0
  | None -> exit 1

let print_diagnostics diagnostics =
  diagnostics
  |> List.iter (fun diagnostic -> prerr_endline (Lpf.Policy.diagnostic_to_string diagnostic))

let handle_check args =
  let rec parse json path = function
    | [] -> Ok (json, path)
    | "--json" :: rest -> parse true path rest
    | option :: _ when String.starts_with ~prefix:"-" option -> Error ("unknown option: " ^ option)
    | arg :: rest -> (
        match path with
        | None -> parse json (Some arg) rest
        | Some _ -> Error "expected exactly one policy path")
  in
  match parse false None args with
  | Ok (json, Some path) ->
      let result = read_file path |> Lpf.check_policy_text ~file:path in
      if json then (
        print_string (Lpf.Policy.check_result_to_json result);
        exit (match result.Lpf.Policy.policy with Some _ -> 0 | None -> 1))
      else exit_for_policy_check result
  | Ok (_, None) ->
      prerr_endline "usage: lpf check [--json] <policy>";
      exit 64
  | Error message ->
      prerr_endline message;
      prerr_endline "usage: lpf check [--json] <policy>";
      exit 64

let handle_fmt args =
  let rec parse check_only json path = function
    | [] -> Ok (check_only, json, path)
    | "--check" :: rest -> parse true json path rest
    | "--json" :: rest -> parse check_only true path rest
    | option :: _ when String.starts_with ~prefix:"-" option -> Error ("unknown option: " ^ option)
    | arg :: rest -> (
        match path with
        | None -> parse check_only json (Some arg) rest
        | Some _ -> Error "expected exactly one policy path")
  in
  match parse false false None args with
  | Ok (check_only, json, Some path) -> (
      let input = read_file path in
      match Lpf.format_policy_text ~file:path input with
      | Ok formatted ->
          if json then
            Printf.printf "{\"formatted\":%s}\n" (Lpf.Json_util.string formatted)
          else if check_only then (
            if String.equal input formatted then (
              Printf.printf "%s is formatted\n" path;
              exit 0)
            else (
              prerr_endline (path ^ " is not formatted");
              exit 1))
          else print_string formatted
      | Error diagnostics ->
          if json then
            Printf.printf "{\"error\":%s,\"diagnostics\":[%s]}\n"
              (Lpf.Json_util.string "formatting failed")
              (String.concat "," (List.map Lpf.Policy.diagnostic_to_json diagnostics))
          else print_diagnostics diagnostics;
          exit 1)
  | Ok (_, _, None) ->
      prerr_endline "usage: lpf fmt [--check] [--json] <policy>";
      exit 64
  | Error message ->
      prerr_endline message;
      prerr_endline "usage: lpf fmt [--check] [--json] <policy>";
      exit 64

let parse_plan_args args =
  let is_option arg = String.length arg > 0 && arg.[0] = '-' in
  let rec loop backend paths = function
    | [] -> Ok (backend, List.rev paths)
    | "--json" :: rest -> loop backend paths rest
    | "--backend" :: "nftables" :: rest -> loop "nftables" paths rest
    | "--backend" :: "tc" :: rest -> loop "tc" paths rest
    | "--backend" :: "routing" :: rest -> loop "routing" paths rest
    | "--backend" :: backend :: _ -> Error ("unsupported backend: " ^ backend)
    | arg :: _ when is_option arg -> Error arg
    | path :: rest -> loop backend (path :: paths) rest
  in
  loop "plan" [] args

let handle_plan args =
  match parse_plan_args args with
  | Error option ->
      prerr_endline ("unknown lpf plan option: " ^ option);
      prerr_endline "usage: lpf plan [--json] [--backend nftables|tc|routing] <policy>";
      exit 64
  | Ok (backend, [ path ]) -> (
      let input = read_file path in
      match backend with
      | "tc" -> (
          match Lpf.render_tc_policy_text ~file:path input with
          | Ok (rendered, diagnostics) ->
              print_diagnostics diagnostics;
              print_string rendered
          | Error diagnostics ->
              print_diagnostics diagnostics;
              exit 1)
      | "routing" -> (
          match Lpf.render_routing_policy_text ~file:path input with
          | Ok (rendered, diagnostics) ->
              print_diagnostics diagnostics;
              print_string rendered
          | Error diagnostics ->
              print_diagnostics diagnostics;
              exit 1)
      | _ -> (
          match Lpf.plan_policy_text ~file:path input with
          | Ok (plan, diagnostics) ->
              print_diagnostics diagnostics;
              print_string (Lpf.Plan.to_json plan)
          | Error diagnostics ->
              print_diagnostics diagnostics;
              exit 1))
  | Ok _ ->
      prerr_endline "usage: lpf plan [--json] [--backend nftables|tc|routing] <policy>";
      exit 64

let parse_rules_args args =
  let rec loop backend paths = function
    | [] -> Ok (backend, List.rev paths)
    | "--backend" :: "nftables" :: rest -> loop "nftables" paths rest
    | "--backend" :: "tc" :: rest -> loop "tc" paths rest
    | "--backend" :: "routing" :: rest -> loop "routing" paths rest
    | "--backend" :: backend :: _ -> Error ("unsupported backend: " ^ backend)
    | option :: _ when String.length option > 0 && option.[0] = '-' ->
        Error ("unknown option: " ^ option)
    | path :: rest -> loop backend (path :: paths) rest
  in
  loop "nftables" [] args

type rules_diff_source =
  | Observed_path of string
  | Live

type rules_diff_args = {
  source : rules_diff_source option;
  policies : string list;
}

let parse_rules_diff_args args =
  let set_source parsed source =
    match parsed.source with
    | None -> Ok { parsed with source = Some source }
    | Some _ -> Error "duplicate observed ruleset source"
  in
  let rec loop parsed = function
    | [] -> Ok { parsed with policies = List.rev parsed.policies }
    | "--backend" :: "nftables" :: rest -> loop parsed rest
    | "--backend" :: "tc" :: rest -> loop parsed rest
    | "--backend" :: "routing" :: rest -> loop parsed rest
    | "--backend" :: backend :: _ -> Error ("unsupported backend: " ^ backend)
    | "--observed" :: observed :: rest -> (
        match set_source parsed (Observed_path observed) with
        | Ok parsed -> loop parsed rest
        | Error message -> Error message)
    | "--observed" :: [] -> Error "missing value for --observed"
    | "--live" :: rest -> (
        match set_source parsed Live with
        | Ok parsed -> loop parsed rest
        | Error message -> Error message)
    | option :: _ when String.length option > 0 && option.[0] = '-' ->
        Error ("unknown option: " ^ option)
    | policy :: rest -> loop { parsed with policies = policy :: parsed.policies } rest
  in
  loop { source = None; policies = [] } args

let read_observed_ruleset = function
  | Observed_path "-" -> Ok (read_stdin ())
  | Observed_path path -> Ok (read_file path)
  | Live -> (
      match Lpf.Nft.list_ruleset () with
      | Ok ruleset -> Ok ruleset
      | Error error -> Error (Lpf.Nft.string_of_run_error error))

let source_name = function
  | Observed_path _ -> "observed"
  | Live -> "live"

let handle_rules = function
  | "show" :: args -> (
      match parse_rules_args args with
      | Error message ->
          prerr_endline message;
          prerr_endline "usage: lpf rules show [--backend nftables|tc|routing] <policy>";
          exit 64
      | Ok (backend, [ path ]) -> (
          let input = read_file path in
          let result = match backend with
            | "tc" -> Lpf.render_tc_policy_text ~file:path input
            | "routing" -> Lpf.render_routing_policy_text ~file:path input
            | _ -> Lpf.render_nftables_policy_text ~file:path input
          in
          match result with
          | Ok (rendered, diagnostics) ->
              print_diagnostics diagnostics;
              print_string rendered
          | Error diagnostics ->
              print_diagnostics diagnostics;
              exit 1)
      | Ok _ ->
          prerr_endline "usage: lpf rules show [--backend nftables|tc|routing] <policy>";
          exit 64)
  | "diff" :: args -> (
      match parse_rules_diff_args args with
      | Error message ->
          prerr_endline message;
          prerr_endline
            "usage: lpf rules diff [--backend nftables] (--observed <ruleset|->|--live) <policy>";
          exit 64
      | Ok { source = Some source; policies = [ path ]; _ } -> (
          match read_observed_ruleset source with
          | Error message ->
              prerr_endline message;
              exit 1
          | Ok observed -> (
              let input = read_file path in
              match Lpf.diff_nftables_policy_text ~file:path ~observed input with
              | Ok (diff, diagnostics) ->
                  print_diagnostics diagnostics;
                  print_string diff
              | Error diagnostics ->
                  print_diagnostics diagnostics;
                  exit 1))
      | Ok _ ->
          prerr_endline
            "usage: lpf rules diff [--backend nftables] (--observed <ruleset|->|--live) <policy>";
          exit 64)
  | [ path ] -> (
      let input = read_file path in
      match Lpf.render_nftables_policy_text ~file:path input with
      | Ok (rendered, diagnostics) ->
          print_diagnostics diagnostics;
          print_string rendered
      | Error diagnostics ->
          print_diagnostics diagnostics;
          exit 1)
  | _ ->
      prerr_endline "usage: lpf rules show [--backend nftables] <policy>";
      exit 64

type diff_args = {
  backend : string;
  json : bool;
  source : rules_diff_source option;
  policies : string list;
}

let parse_diff_args args =
  let set_source parsed source =
    match parsed.source with
    | None -> Ok { parsed with source = Some source }
    | Some _ -> Error "duplicate observed ruleset source"
  in
  let rec loop parsed = function
    | [] -> Ok { parsed with policies = List.rev parsed.policies }
    | "--json" :: rest -> loop { parsed with json = true } rest
    | "--backend" :: "nftables" :: rest -> loop { parsed with backend = "nftables" } rest
    | "--backend" :: "tc" :: rest -> loop { parsed with backend = "tc" } rest
    | "--backend" :: "routing" :: rest -> loop { parsed with backend = "routing" } rest
    | "--backend" :: backend :: _ -> Error ("unsupported backend: " ^ backend)
    | "--observed" :: observed :: rest -> (
        match set_source parsed (Observed_path observed) with
        | Ok parsed -> loop parsed rest
        | Error message -> Error message)
    | "--observed" :: [] -> Error "missing value for --observed"
    | "--live" :: rest -> (
        match set_source parsed Live with
        | Ok parsed -> loop parsed rest
        | Error message -> Error message)
    | option :: _ when String.length option > 0 && option.[0] = '-' ->
        Error ("unknown option: " ^ option)
    | policy :: rest -> loop { parsed with policies = policy :: parsed.policies } rest
  in
  loop { backend = "nftables"; json = false; source = None; policies = [] } args

let json_string text = Lpf.Json_util.string text
let json_bool value = if value then "true" else "false"

let diff_json ~source (diff : Lpf.Nftables.diff_result) =
  String.concat "\n"
    [
      "{";
      "  \"version\": 1,";
      "  \"backend\": \"nftables\",";
      "  \"source\": " ^ json_string (source_name source) ^ ",";
      "  \"changes_required\": " ^ json_bool diff.changes_required ^ ",";
      "  \"diff\": " ^ json_string diff.text;
      "}";
      "";
    ]

let handle_diff args =
  match parse_diff_args args with
  | Error message ->
      prerr_endline message;
      prerr_endline
        "usage: lpf diff [--backend nftables|tc|routing] [--observed <text|->|--live] [--json] <policy>";
      exit 64
  | Ok { backend; source; policies = [ path ]; json } ->
      let source = Option.value source ~default:Live in
      let input = read_file path in
       (match backend with
       | "tc" ->
            (match source with
             | Observed_path p ->
                 let observed = read_file p in
                 (match Lpf.render_tc_policy_text ~file:path input with
                  | Ok (rendered, diagnostics) ->
                      print_diagnostics diagnostics;
                      let changes = not (String.equal rendered observed) in
                      let diff_out = if changes then Printf.sprintf "--- expected\n+++ observed\n-%s+%s" rendered observed else "no changes" in
                      if json then Printf.printf "{\"backend\":\"tc\",\"changes_required\":%B}\n" changes
                      else print_endline diff_out
                  | Error diagnostics ->
                      print_diagnostics diagnostics;
                      exit 1)
             | Live ->
                 let plan = match Lpf.plan_policy_text ~file:path input with
                   | Ok (plan, _) -> plan
                   | Error _ -> Lpf.Plan.of_ir {
                     Lpf.Ir.default_action = Lpf.Policy.Default_deny;
                     interfaces = []; tables = []; queues = [];
                     nats = []; rdrs = []; anchors = []; rules = [];
                   }
                 in
                 let devices = plan.Lpf.Plan.policy.Lpf.Ir.interfaces |> List.map (fun i -> i.Lpf.Ir.device) in
                 let devices = if devices = [] then [ "eth0" ] else devices in
                 let observed_qdiscs = List.concat_map (fun dev ->
                   match Lpf.Tc.qdisc_show dev with Ok s -> Lpf.Tc.parse_qdisc_show dev s | _ -> []) devices in
                 let observed_classes = List.concat_map (fun dev ->
                   match Lpf.Tc.class_show dev with Ok s -> Lpf.Tc.parse_class_show dev s | _ -> []) devices in
                 (match Lpf.diff_tc_policy ~file:path ~observed_qdisc:observed_qdiscs ~observed_class:observed_classes input with
                  | Ok (diff, diagnostics) ->
                      print_diagnostics diagnostics;
                      if json then Printf.printf "{\"backend\":\"tc\",\"changes_required\":%B}\n" diff.Lpf.Tc.changes_required
                      else print_endline diff.Lpf.Tc.text
                  | Error diagnostics ->
                      print_diagnostics diagnostics;
                      exit 1))
       | "routing" ->
            (match source with
             | Observed_path p ->
                 let observed = read_file p in
                 (match Lpf.render_routing_policy_text ~file:path input with
                  | Ok (rendered, diagnostics) ->
                      print_diagnostics diagnostics;
                      let changes = not (String.equal rendered observed) in
                      let diff_out = if changes then Printf.sprintf "--- expected\n+++ observed\n-%s+%s" rendered observed else "no changes" in
                      if json then Printf.printf "{\"backend\":\"routing\",\"changes_required\":%B}\n" changes
                      else print_endline diff_out
                  | Error diagnostics ->
                      print_diagnostics diagnostics;
                      exit 1)
             | Live ->
                 let rule_text = match Lpf.Ip.rule_list () with Ok s -> s | _ -> "" in
                 let observed_rules = Lpf.Ip.parse_rule_list rule_text in
                 let plan = match Lpf.plan_policy_text ~file:path input with
                   | Ok (plan, _) -> plan
                   | Error _ -> Lpf.Plan.of_ir {
                     Lpf.Ir.default_action = Lpf.Policy.Default_deny;
                     interfaces = []; tables = []; queues = [];
                     nats = []; rdrs = []; anchors = []; rules = [];
                   }
                 in
                 let tables_needed =
                   let cmds = Lpf.Routing.compile plan.Lpf.Plan.policy in
                   List.filter_map (function
                     | Lpf.Routing.Ip_route_add_default r -> Some r.table
                     | _ -> None) cmds in
                 let observed_routes = List.concat_map (fun table ->
                   match Lpf.Ip.route_show table with
                   | Ok s -> List.map (fun x -> { x with Lpf.Ip.table }) (Lpf.Ip.parse_route_show s)
                   | _ -> []) tables_needed in
                 (match Lpf.diff_routing_policy ~file:path ~observed_rules ~observed_routes input with
                  | Ok (diff, diagnostics) ->
                      print_diagnostics diagnostics;
                      if json then Printf.printf "{\"backend\":\"routing\",\"changes_required\":%B}\n" diff.Lpf.Routing.changes_required
                      else print_endline diff.Lpf.Routing.text
                  | Error diagnostics ->
                      print_diagnostics diagnostics;
                      exit 1))
       | _ ->
           (match read_observed_ruleset source with
            | Error message ->
                prerr_endline message;
                exit 1
            | Ok observed ->
                (match Lpf.diff_nftables_policy ~file:path ~observed input with
                 | Ok (diff, diagnostics) ->
                     print_diagnostics diagnostics;
                     if json then print_string (diff_json ~source diff) else print_string diff.text
                 | Error diagnostics ->
                     print_diagnostics diagnostics;
                     exit 1)))
  | Ok _ ->
      prerr_endline
        "usage: lpf diff [--backend nftables|tc|routing] [--observed <text|->|--live] [--json] <policy>";
      exit 64

let handle_apply args =
  let dry_run = List.mem "--dry-run" args in
  let rec parse confirm paths = function
    | [] -> (confirm, List.rev paths)
    | "--confirm" :: duration :: rest -> parse (Some duration) paths rest
    | "--dry-run" :: rest -> parse confirm paths rest
    | arg :: rest when String.length arg > 0 && arg.[0] = '-' -> parse confirm paths rest
    | path :: rest -> parse confirm (path :: paths) rest
  in
  let confirm, paths = parse None [] args in
  match paths with
  | [ path ] when dry_run -> (
      let input = read_file path in
      match Lpf.plan_policy_text ~file:path input with
      | Ok (plan, diagnostics) ->
          print_diagnostics diagnostics;
          Printf.printf "dry-run: plan checksum %s, %d interfaces, %d rules\n"
            (Lpf.Plan.checksum plan)
            (List.length plan.Lpf.Plan.policy.Lpf.Ir.interfaces)
            (List.length plan.Lpf.Plan.policy.Lpf.Ir.rules);
          exit 0
      | Error diagnostics ->
          print_diagnostics diagnostics;
          exit 1)
  | [ path ] -> (
      let input = read_file path in
      match Lpf.apply_policy_text ?confirm ~file:path input with
      | Ok ((), diagnostics) ->
          print_diagnostics diagnostics;
          if confirm <> None then
            Printf.printf "guarded apply of %s started; use lpf confirm to promote\n" path
          else Printf.printf "applied %s\n" path;
          exit 0
      | Error diagnostics ->
          print_diagnostics diagnostics;
          exit 1)
  | _ ->
      prerr_endline "usage: lpf apply [--confirm <duration>] <policy>";
      exit 64

let handle_confirm () =
  match Lpf.confirm () with
  | Ok ((), diagnostics) ->
      print_diagnostics diagnostics;
      Printf.printf "apply confirmed\n";
      exit 0
  | Error diagnostics ->
      print_diagnostics diagnostics;
      exit 1

let handle_rollback args =
  let now = List.exists (String.equal "--now") args in
  if now then
    match Lpf.rollback_now () with
    | Ok ((), diagnostics) ->
        print_diagnostics diagnostics;
        Printf.printf "rolled back to preimage\n";
        exit 0
    | Error diagnostics ->
        print_diagnostics diagnostics;
        exit 1
  else
    let policy_id = List.find_opt (fun a -> not (String.starts_with ~prefix:"-" a)) args in
    match policy_id with
    | Some id -> (
        match Lpf.Apply_guard.rollback_by_id id with
        | Ok ((), diagnostics) ->
            print_diagnostics diagnostics;
            Printf.printf "rolled back to policy %s\n" id;
            exit 0
        | Error diagnostics ->
            print_diagnostics diagnostics;
            exit 1)
    | None ->
        prerr_endline "usage: lpf rollback [--now] [<policy-id>]";
        exit 64

let handle_explain args =
  let json, args =
    List.fold_left
      (fun (json, rest) arg ->
        if String.equal arg "--json" then (true, rest) else (json, rest @ [ arg ]))
      (false, []) args
  in
  let rec parse_packet pkt = function
    | [] -> pkt
    | "from" :: addr :: rest -> parse_packet { pkt with Lpf.Explain.source = addr } rest
    | "to" :: addr :: rest -> parse_packet { pkt with Lpf.Explain.destination = addr } rest
    | "proto" :: proto :: rest ->
        let p = if String.equal proto "any" then Lpf.Policy.Proto_any else Lpf.Policy.Proto_named proto in
        parse_packet { pkt with Lpf.Explain.protocol = p } rest
    | "port" :: port :: rest ->
        let p = int_of_string_opt port in
        parse_packet { pkt with Lpf.Explain.port = p } rest
    | ("in" | "on") :: iface :: rest ->
        parse_packet { pkt with Lpf.Explain.interface = iface } rest
    | "out" :: rest ->
        parse_packet { pkt with Lpf.Explain.direction = Lpf.Policy.Out } rest
    | _ :: rest -> parse_packet pkt rest
  in
  let initial_pkt = {
    Lpf.Explain.direction = Lpf.Policy.In;
    interface = "eth0";
    protocol = Lpf.Policy.Proto_any;
    source = "0.0.0.0";
    destination = "0.0.0.0";
    port = None;
  } in
  let policy_path = List.find_opt (fun arg -> String.ends_with ~suffix:".lpf" arg || String.equal arg "/etc/lpf.conf") args in
  match policy_path with
  | None ->
      prerr_endline "usage: lpf explain [--json] [in|on <iface>] [from <addr>] [to <addr>] [proto <proto>] [port <port>] <policy>";
      exit 64
  | Some path ->
      let pkt = parse_packet initial_pkt args in
      let input = read_file path in
      match Lpf.explain_policy_text ~file:path ~packet:pkt input with
      | Ok (explanation, diagnostics) ->
          print_diagnostics diagnostics;
          if json then print_endline (Lpf.Explain.to_json explanation)
          else print_endline (Lpf.Explain.to_string explanation);
          exit 0
      | Error diagnostics ->
          print_diagnostics diagnostics;
          exit 1

let handle_test args =
  let junit_path, paths =
    let rec find junit_path paths = function
      | [] -> (junit_path, List.rev paths)
      | "--junit" :: path :: rest -> find (Some path) paths rest
      | path :: rest -> find junit_path (path :: paths) rest
    in
    find None [] args
  in
  match paths with
  | [ path ] -> (
      let input = read_file path in
      match Lpf.run_policy_tests ~file:path input with
      | Ok (results, diagnostics) ->
          print_diagnostics diagnostics;
          let total_tests = List.fold_left (fun acc (_, r) -> acc + List.length r) 0 results in
          let total_failed =
            List.fold_left
              (fun acc (_, r) ->
                acc + List.length (List.filter (function Lpf.Test_engine.Fail _ -> true | _ -> false) r))
              0 results
          in
          List.iter
            (fun (case, r) ->
              Printf.printf "Test: %s\n" case.Lpf.Test_engine.name;
              List.iteri
                (fun i result ->
                  match result with
                  | Lpf.Test_engine.Pass -> Printf.printf "  expectation %d: ok\n" i
                   | Lpf.Test_engine.Fail { expected; actual; explanation } ->
                       Printf.printf "  expectation %d: FAILED (expected %s but got %s)\n" i
                         (Lpf.Policy.string_of_action expected)
                         (Lpf.Policy.string_of_action actual);
                      let explanation_text = Lpf.Explain.to_string explanation in
                      let lines = String.split_on_char '\n' explanation_text in
                      List.iter (fun line -> Printf.printf "    %s\n" line) lines)
                r)
            results;
          (match junit_path with
          | Some jpath ->
              let xml = Lpf.Test_engine.to_junit results in
              write_file jpath xml
          | None -> ());
          if total_failed > 0 then (
            Printf.printf "\nFAILED: %d failed, %d passed, %d total\n" total_failed
              (total_tests - total_failed) total_tests;
            exit 1)
          else (
            Printf.printf "\nOK: %d passed\n" total_tests;
            exit 0)
      | Error diagnostics ->
          print_diagnostics diagnostics;
          exit 1)
  | _ ->
      prerr_endline "usage: lpf test [--junit <path>] <fixture>";
      exit 64

let handle_history args =
  let json = List.exists (String.equal "--json") args in
  match Lpf.get_history () with
  | Ok (h, diagnostics) ->
      print_diagnostics diagnostics;
      if json then print_endline (Lpf.History.to_json h)
      else print_endline (Lpf.History.to_string h);
      exit 0
  | Error diagnostics ->
      print_diagnostics diagnostics;
      exit 1

let handle_state args =
  let json = List.mem "--json" args in
  let sub = List.find_opt (fun a -> not (String.starts_with ~prefix:"-" a)) args in
  match sub with
  | Some "list" -> (
      match Lpf.Conntrack.list () with
      | Ok output ->
          let entries = Lpf.Conntrack.parse_list output in
          if json then print_string (Lpf.Conntrack.entries_to_json entries)
          else List.iter (fun (e : Lpf.Conntrack.conntrack_entry) -> Printf.printf "%s %s %s %s %s [%s]\n" e.protocol e.src e.dst e.sport e.dport e.state) entries;
          exit 0
      | Error error ->
          prerr_endline (Lpf.Conntrack.string_of_run_error error);
          exit 1)
  | Some "flush" -> (
      match Lpf.Conntrack.flush () with
      | Ok () ->
          if json then Printf.printf "{\"status\":\"flushed\"}\n"
          else Printf.printf "conntrack table flushed\n";
          exit 0
      | Error error ->
          prerr_endline (Lpf.Conntrack.string_of_run_error error);
          exit 1)
  | Some "kill" ->
      let rest = List.filter (fun a -> a <> "kill" && a <> "--json") args in
      let rec parse_src_dst src dst = function
        | [] -> (src, dst)
        | "--src" :: s :: more -> parse_src_dst (Some s) dst more
        | "--dst" :: d :: more -> parse_src_dst src (Some d) more
        | _ :: more -> parse_src_dst src dst more
      in
      let src, dst = parse_src_dst None None rest in
      (match (src, dst) with
       | Some s, Some d -> (
           match Lpf.Conntrack.delete ~src:s ~dst:d with
           | Ok () ->
               Printf.printf "deleted conntrack entries for %s -> %s\n" s d;
               exit 0
           | Error error ->
               prerr_endline (Lpf.Conntrack.string_of_run_error error);
               exit 1)
       | _ ->
           prerr_endline "state kill: specify --src and --dst addresses";
           exit 64)
  | Some "show" -> (
      match Lpf.Conntrack.list () with
      | Ok output ->
          let entries = Lpf.Conntrack.parse_list output in
          if json then print_string (Lpf.Conntrack.entries_to_json entries)
          else List.iter (fun (e : Lpf.Conntrack.conntrack_entry) ->
              Printf.printf "%s %s %s %s %s [%s]\n"
                e.protocol e.src e.dst e.sport e.dport e.state)
            entries;
          exit 0
      | Error error ->
          prerr_endline (Lpf.Conntrack.string_of_run_error error);
          exit 1)
  | _ ->
      prerr_endline "usage: lpf state [--json] <list|show|flush|kill>";
      exit 64

let handle_table args =
  let json = List.mem "--json" args in
  let clean args = List.filter (fun a -> a <> "--json") args in
  match clean args with
  | name :: "add" :: element :: _ -> (
      match Lpf.Table.add name element with
      | Ok () ->
          Printf.printf "added %s to table %s\n" element name;
          exit 0
      | Error error ->
          prerr_endline (Lpf.Nft.string_of_run_error error);
          exit 1)
  | name :: "delete" :: element :: _ -> (
      match Lpf.Table.delete name element with
      | Ok () ->
          Printf.printf "deleted %s from table %s\n" element name;
          exit 0
      | Error error ->
          prerr_endline (Lpf.Nft.string_of_run_error error);
          exit 1)
  | name :: "replace" :: rest ->
      let elements = List.filter (fun s -> String.length s > 0 && not (String.starts_with ~prefix:"-" s)) rest in
      (match Lpf.Table.replace name elements with
       | Ok () ->
           Printf.printf "replaced table %s with %d elements\n" name (List.length elements);
           exit 0
       | Error error ->
           prerr_endline (Lpf.Nft.string_of_run_error error);
           exit 1)
  | name :: "show" :: _ -> (
      match Lpf.Table.counters name with
      | Ok output ->
          if json then print_string (Lpf.Table.elements_to_json (Lpf.Table.parse_counters_output output))
          else print_endline output;
          exit 0
      | Error error ->
          prerr_endline (Lpf.Nft.string_of_run_error error);
          exit 1)
  | name :: "counters" :: _ -> (
      match Lpf.Table.counters name with
      | Ok output ->
          if json then print_string (Lpf.Table.elements_to_json (Lpf.Table.parse_counters_output output))
          else print_endline output;
          exit 0
      | Error error ->
          prerr_endline (Lpf.Nft.string_of_run_error error);
          exit 1)
  | name :: "flush" :: _ -> (
      match Lpf.Table.flush name with
      | Ok () ->
          Printf.printf "flushed table %s\n" name;
          exit 0
      | Error error ->
          prerr_endline (Lpf.Nft.string_of_run_error error);
          exit 1)
  | _ ->
      prerr_endline "usage: lpf table <name> <add|delete|replace|show|flush|counters> [...]";
      exit 64

let handle_ebpf args =
  let policy_opt = List.find_opt (fun a -> String.ends_with ~suffix:".lpf" a || String.equal a "/etc/lpf.conf") args in
  match policy_opt with
  | None ->
      prerr_endline "usage: lpf ebpf <policy>";
      exit 64
  | Some path -> (
      let input = read_file path in
      let result = Lpf.check_policy_text ~file:path input in
      match result.policy with
      | None ->
          print_diagnostics result.diagnostics;
          exit 1
      | Some policy -> (
          match Lpf.ir_of_policy policy with
          | Error diagnostics ->
              print_diagnostics (result.diagnostics @ diagnostics);
              exit 1
          | Ok ir ->
              print_diagnostics result.diagnostics;
              print_string (Lpf.Ebpf.compile_to_c ir);
              exit 0))

let parse_e2e_args args =
  let rec loop mode scenario_count junit_path allure_dir evidence_dir kernel_id dry_run = function
    | [] -> Ok (mode, scenario_count, junit_path, allure_dir, evidence_dir, kernel_id, dry_run)
    | "run" :: rest -> loop "run" scenario_count junit_path allure_dir evidence_dir kernel_id dry_run rest
    | "list" :: rest -> loop "list" scenario_count junit_path allure_dir evidence_dir kernel_id dry_run rest
    | "--scenario-count" :: value :: rest -> (
        match int_of_string_opt value with
        | Some count -> loop mode count junit_path allure_dir evidence_dir kernel_id dry_run rest
        | None -> Error ("invalid --scenario-count: " ^ value))
    | "--scenario-count" :: [] -> Error "missing value for --scenario-count"
    | "--junit" :: path :: rest -> loop mode scenario_count (Some path) allure_dir evidence_dir kernel_id dry_run rest
    | "--junit" :: [] -> Error "missing value for --junit"
    | "--allure-dir" :: path :: rest ->
        loop mode scenario_count junit_path (Some path) evidence_dir kernel_id dry_run rest
    | "--allure-dir" :: [] -> Error "missing value for --allure-dir"
    | "--evidence-dir" :: path :: rest ->
        loop mode scenario_count junit_path allure_dir (Some path) kernel_id dry_run rest
    | "--evidence-dir" :: [] -> Error "missing value for --evidence-dir"
    | "--kernel-id" :: value :: rest ->
        loop mode scenario_count junit_path allure_dir evidence_dir (Some value) dry_run rest
    | "--kernel-id" :: [] -> Error "missing value for --kernel-id"
    | "--dry-run" :: rest -> loop mode scenario_count junit_path allure_dir evidence_dir kernel_id true rest
    | option :: _ when String.length option > 0 && option.[0] = '-' -> Error ("unknown option: " ^ option)
    | value :: _ -> Error ("unknown lpf e2e argument: " ^ value)
  in
  loop "run" Lpf.E2e.default_scenario_count None None None None false args

let handle_e2e args =
  match parse_e2e_args args with
  | Error message ->
      prerr_endline message;
      prerr_endline
        "usage: lpf e2e <run|list> [--scenario-count 1..1000] [--junit PATH] [--allure-dir DIR] [--evidence-dir DIR] [--kernel-id ID] [--dry-run]";
      exit 64
  | Ok ("list", scenario_count, _, _, _, _, _) ->
      (try
         Lpf.E2e.scenario_catalog scenario_count
         |> List.iter (fun scenario ->
                Printf.printf "%s\t%s\t%s\n" scenario.Lpf.E2e.id
                  (Lpf.E2e.family_name scenario.family)
                  scenario.description);
         exit 0
       with Invalid_argument message ->
         prerr_endline message;
         exit 1)
  | Ok (_, scenario_count, junit_path, allure_dir, evidence_dir, kernel_id, dry_run) -> (
      try
        let result =
          Lpf.E2e.run { scenario_count; junit_path; allure_dir; evidence_dir; kernel_id; dry_run }
        in
        Printf.printf "lpf e2e: %d passed, %d failed, %d total on %s (%s)\n" result.passed
          result.failed result.scenario_count result.kernel_id result.kernel_release;
        if result.failed = 0 then exit 0 else exit 1
       with Failure message | Invalid_argument message ->
         prerr_endline message;
          exit 1)

let tool_property_name option_name =
  let token =
    option_name
    |> String.trim
    |> String.split_on_char ' '
    |> function
    | first :: _ -> first
    | [] -> option_name
  in
  let token =
    if String.starts_with ~prefix:"--" token then
      String.sub token 2 (String.length token - 2)
    else token
  in
  let buffer = Buffer.create (String.length token) in
  String.iter
    (fun character ->
      let code = Char.code character in
      let valid =
        (code >= Char.code 'a' && code <= Char.code 'z')
        || (code >= Char.code 'A' && code <= Char.code 'Z')
        || (code >= Char.code '0' && code <= Char.code '9')
      in
      Buffer.add_char buffer (if valid then character else '_'))
    token;
  let name = Buffer.contents buffer in
  if String.length name = 0 then "option" else name

let deduplicate_properties properties =
  let rec loop seen acc = function
    | [] -> List.rev acc
    | ((name, _) as property) :: rest ->
        if List.mem name seen then loop seen acc rest
        else loop (name :: seen) (property :: acc) rest
  in
  loop [] [] properties

let tool_schema_properties doc =
  let option_properties =
    match doc with
    | None -> []
    | Some d ->
        List.map
          (fun (opt_name, opt_desc) -> (tool_property_name opt_name, ("string", opt_desc)))
          d.Lpf.options
  in
  deduplicate_properties (option_properties @ [ ("policy", ("string", "the policy text")) ])

let tool_schema_openai (name, command, summary) =
  let doc = List.find_opt (fun d -> d.Lpf.command = command) Lpf.command_docs in
  let properties = tool_schema_properties doc in
  let required = ["policy"] in
  let props_json =
    String.concat ","
      (List.map
         (fun (k, (t, desc)) ->
           Printf.sprintf "%s:{\"type\":%s,\"description\":%s}"
             (Lpf.Json_util.string k) (Lpf.Json_util.string t) (Lpf.Json_util.string desc))
         properties)
  in
  Printf.sprintf
    "{\"name\":%s,\"description\":%s,\"parameters\":{\"type\":\"object\",\"properties\":{%s},\"required\":%s}}"
    (Lpf.Json_util.string name) (Lpf.Json_util.string summary) props_json
    (Lpf.Json_util.list Lpf.Json_util.string required)

let tool_schema_jsonschema (name, _command, summary) =
  Printf.sprintf "{\"$id\":%s,\"title\":%s,\"description\":%s,\"type\":\"object\",\"properties\":{\"policy\":{\"type\":\"string\",\"description\":\"the lpf policy text\"}},\"required\":[\"policy\"]}"
    (Lpf.Json_util.string ("lpf-" ^ name))
    (Lpf.Json_util.string name)
    (Lpf.Json_util.string summary)

let handle_tools args =
  let rec parse format = function
    | [] -> Ok format
    | "--format" :: ("openai" as value) :: rest -> parse value rest
    | "--format" :: ("jsonschema" as value) :: rest -> parse value rest
    | "--format" :: ("system-prompt" as value) :: rest -> parse value rest
    | "--format" :: value :: _ -> Error ("unsupported tools format: " ^ value)
    | "--format" :: [] -> Error "missing value for --format"
    | option :: _ when String.starts_with ~prefix:"-" option -> Error ("unknown option: " ^ option)
    | value :: _ -> Error ("unknown lpf tools argument: " ^ value)
  in
  match parse "openai" args with
  | Error message ->
      prerr_endline message;
      prerr_endline "usage: lpf tools [--format openai|jsonschema|system-prompt]";
      exit 64
  | Ok format ->
      if String.equal format "system-prompt" then (
        print_endline
          (Lpf.Json_util.string
             ("You are an lpf firewall automation agent. lpf is an OCaml control plane for Linux networking that compiles a PF-inspired policy language to nftables, policy routing, tc traffic shaping, and conntrack.\n\
               \n\
               Commands available:\n\
               - lpf check <policy> - Parse and validate a policy without host changes. Use --json for structured output.\n\
               - lpf fmt <policy> - Format policy files deterministically. Use --json for machine output.\n\
               - lpf plan --json <policy> - Compile policy to a versioned JSON plan with stable checksum.\n\
               - lpf diff --json <policy> - Compare intended state with live nftables/routing/tc state.\n\
               - lpf apply <policy> [--confirm 60s] - Apply policy with atomic rollback support.\n\
               - lpf apply --dry-run <policy> - Validate and plan without changing host state.\n\
               - lpf explain --json from <addr> to <addr> proto <proto> port <port> <policy> - Explain packet handling.\n\
               - lpf test --junit <path> <fixture> - Run policy assertion tests.\n\
               - lpf table <name> <add|delete|replace|show|flush|counters> [--json] - Manage dynamic tables.\n\
               - lpf state <list|show|flush|kill> [--json] - Inspect conntrack state.\n\
               - lpf history [--json] - Show policy apply history.\n\
               - lpf rollback [--now] [<policy-id>] - Restore previous policy.\n\
               - lpf confirm - Confirm pending guarded apply.\n\
               \n\
               Safety: Always use lpf check before apply. Use guarded apply (--confirm) for remote hosts. Use rollback if traffic is disrupted. lpf requires root/CAP_NET_ADMIN.\n\
               \n\
               When writing policies, follow the lpf policy format: interfaces, tables, macros, NAT, RDR, queues, anchors, and rules with pass/block/reject actions. Use lpf fmt to normalize before applying."));
        exit 0)
      else
        let tools =
          List.filter
            (fun (_name, cmd, _) ->
              match cmd with
              | Lpf.Check | Lpf.Fmt | Lpf.Plan | Lpf.Diff | Lpf.Apply | Lpf.Explain
              | Lpf.Test | Lpf.Table | Lpf.State | Lpf.Rules | Lpf.History ->
                  true
              | _ -> false)
            Lpf.all_commands
        in
        let render =
          match format with
          | "jsonschema" -> tool_schema_jsonschema
          | _ -> tool_schema_openai
        in
        let schemas = List.map render tools in
        Printf.printf "[%s]\n" (String.concat ",\n " schemas);
        exit 0

let () =
  match Array.to_list Sys.argv with
  | [ _ ] | [ _; "--help" ] | [ _; "-h" ] | [ _; "help" ] ->
      print_end (Lpf.help ())
  | [ _; "version" ] | [ _; "--version" ] ->
      print_end Lpf.version
  | [ _; "help"; name ] -> (
      match Lpf.command_of_string name with
      | Some command -> print_end (Lpf.command_help command)
      | None ->
          prerr_endline ("unknown lpf command: " ^ name);
          exit 64)
  | _ :: "check" :: args -> handle_check args
  | _ :: "fmt" :: args -> handle_fmt args
  | _ :: "plan" :: args -> handle_plan args
  | _ :: "diff" :: args -> handle_diff args
  | _ :: "apply" :: args -> handle_apply args
  | _ :: "confirm" :: _ -> handle_confirm ()
  | _ :: "rollback" :: args -> handle_rollback args
  | _ :: "explain" :: args -> handle_explain args
  | _ :: "test" :: args -> handle_test args
  | _ :: "history" :: args -> handle_history args
  | _ :: "rules" :: args -> handle_rules args
  | _ :: "state" :: args -> handle_state args
  | _ :: "e2e" :: args -> handle_e2e args
  | _ :: "ebpf" :: args -> handle_ebpf args
  | _ :: "table" :: args -> handle_table args
  | _ :: "man" :: args -> handle_man args
  | _ :: "tools" :: args -> handle_tools args
  | _ :: name :: _ -> (
      match Lpf.command_of_string name with
      | Some Lpf.Version -> print_end Lpf.version
      | Some Lpf.Help -> print_end (Lpf.help ())
      | Some _ -> ()
      | None ->
          prerr_endline ("unknown lpf command: " ^ name);
          exit 64)
  | [] ->
      prerr_endline "unexpected empty argument vector";
      exit 1
