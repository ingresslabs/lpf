type scenario_family =
  | Nft_accept
  | Nft_drop
  | Nft_log
  | Routing
  | Traffic_shaping
  | Conntrack

type scenario = {
  id : string;
  family : scenario_family;
  index : int;
  description : string;
}

type scenario_status =
  | Passed
  | Failed of string

type scenario_result = {
  scenario : scenario;
  status : scenario_status;
  stdout : string;
  stderr : string;
  duration_ms : int;
}

type config = {
  scenario_count : int;
  junit_path : string option;
  allure_dir : string option;
  evidence_dir : string option;
  kernel_id : string option;
  dry_run : bool;
}

type suite_result = {
  kernel_id : string;
  kernel_release : string;
  scenario_count : int;
  passed : int;
  failed : int;
  results : scenario_result list;
}

type invocation = {
  program : string;
  argv : string list;
}

type process_result = {
  code : int;
  stdout : string;
  stderr : string;
}

type context = {
  ns_a : string;
  ns_b : string;
  veth_a : string;
  veth_b : string;
}

let default_scenario_count = 480
let max_scenario_count = 1000

let validate_scenario_count count =
  if count < 1 || count > max_scenario_count then
    invalid_arg (Printf.sprintf "scenario_count must be between 1 and %d" max_scenario_count)

let family_name = function
  | Nft_accept -> "nftables-accept"
  | Nft_drop -> "nftables-drop"
  | Nft_log -> "nftables-log"
  | Routing -> "policy-routing"
  | Traffic_shaping -> "traffic-shaping"
  | Conntrack -> "conntrack"

let family_of_index index =
  match index mod 6 with
  | 0 -> Nft_accept
  | 1 -> Nft_drop
  | 2 -> Nft_log
  | 3 -> Routing
  | 4 -> Traffic_shaping
  | _ -> Conntrack

let description family variant =
  match family with
  | Nft_accept ->
      Printf.sprintf "accept ICMP traffic through an lpf-owned nftables input rule variant %03d"
        variant
  | Nft_drop ->
      Printf.sprintf "drop ICMP traffic through an lpf-owned nftables input rule variant %03d"
        variant
  | Nft_log ->
      Printf.sprintf "log and accept ICMP traffic through an lpf-owned nftables rule variant %03d"
        variant
  | Routing -> Printf.sprintf "install and verify policy routing table variant %03d" variant
  | Traffic_shaping ->
      Printf.sprintf "install and verify HTB traffic shaping class variant %03d" variant
  | Conntrack -> Printf.sprintf "exercise traffic and inspect conntrack statistics variant %03d" variant

let scenario_catalog count =
  validate_scenario_count count;
  List.init count (fun index ->
      let family = family_of_index index in
      let variant = (index / 6) + 1 in
      {
        id = Printf.sprintf "lpf-e2e-%03d-%s" (index + 1) (family_name family);
        family;
        index = index + 1;
        description = description family variant;
      })

let read_file path =
  let channel = open_in path in
  Fun.protect
    ~finally:(fun () -> close_in channel)
    (fun () ->
      let length = in_channel_length channel in
      really_input_string channel length)

let write_file path content =
  let channel = open_out path in
  Fun.protect
    ~finally:(fun () -> close_out channel)
    (fun () -> output_string channel content)

let rec ensure_dir dir =
  if dir = "" || dir = "." || dir = Filename.dirname dir then ()
  else if Sys.file_exists dir then (
    if not (Sys.is_directory dir) then failwith (dir ^ " exists and is not a directory"))
  else (
    ensure_dir (Filename.dirname dir);
    Unix.mkdir dir 0o755)

let close_noerr fd = try Unix.close fd with Unix.Unix_error _ -> ()

let with_temp_file prefix f =
  let path = Filename.temp_file prefix ".txt" in
  Fun.protect ~finally:(fun () -> if Sys.file_exists path then Sys.remove path) (fun () -> f path)

let exit_code_of_status = function
  | Unix.WEXITED code -> code
  | Unix.WSIGNALED signal -> 128 + signal
  | Unix.WSTOPPED signal -> 128 + signal

let command_line invocation = String.concat " " invocation.argv

let command_log label invocation result =
  String.concat "\n"
    [
      "## " ^ label;
      "$ " ^ command_line invocation;
      "exit=" ^ string_of_int result.code;
      "stdout:";
      result.stdout;
      "stderr:";
      result.stderr;
      "";
    ]

let success_result stdout = { code = 0; stdout; stderr = "" }

let run_command invocation =
  with_temp_file "lpf-e2e-stdout" (fun stdout_path ->
      with_temp_file "lpf-e2e-stderr" (fun stderr_path ->
          let stdout_fd = Unix.openfile stdout_path [ Unix.O_WRONLY; Unix.O_TRUNC ] 0o600 in
          let stderr_fd = Unix.openfile stderr_path [ Unix.O_WRONLY; Unix.O_TRUNC ] 0o600 in
          match
            try
              let pid =
                Unix.create_process invocation.program
                  (Array.of_list invocation.argv) Unix.stdin stdout_fd stderr_fd
              in
              close_noerr stdout_fd;
              close_noerr stderr_fd;
              let _, status = Unix.waitpid [] pid in
              Ok
                {
                  code = exit_code_of_status status;
                  stdout = read_file stdout_path;
                  stderr = read_file stderr_path;
                }
            with Unix.Unix_error (error, function_name, argument) ->
              close_noerr stdout_fd;
              close_noerr stderr_fd;
              Error (Unix.error_message error ^ " in " ^ function_name ^ "(" ^ argument ^ ")")
          with
          | Ok result -> result
          | Error message -> { code = 127; stdout = ""; stderr = message }))

let invocation program argv = { program; argv = program :: argv }

let expect_success invocation =
  let result = run_command invocation in
  if result.code = 0 then Ok result
  else
    Error
      (Printf.sprintf "%s exited %d%s" (command_line invocation) result.code
         (if String.trim result.stderr = "" then "" else ": " ^ String.trim result.stderr))

let ignore_result invocation = ignore (run_command invocation)
let ip args = invocation "ip" args
let nft args = invocation "nft" args
let tc args = invocation "tc" args
let netns_exec ns program args = ip ("netns" :: "exec" :: ns :: program :: args)

let make_context () =
  let seed = (Unix.getpid () lxor int_of_float (Unix.time ())) land 0xfffff in
  let suffix = Printf.sprintf "%05x" seed in
  {
    ns_a = "lpf_e2e_" ^ suffix ^ "_a";
    ns_b = "lpf_e2e_" ^ suffix ^ "_b";
    veth_a = "lea" ^ suffix;
    veth_b = "leb" ^ suffix;
  }

let setup_context ctx =
  ensure_dir "/run/netns";
  ignore_result (ip [ "netns"; "delete"; ctx.ns_a ]);
  ignore_result (ip [ "netns"; "delete"; ctx.ns_b ]);
  [
    ip [ "netns"; "add"; ctx.ns_a ];
    ip [ "netns"; "add"; ctx.ns_b ];
    ip [ "link"; "add"; ctx.veth_a; "type"; "veth"; "peer"; "name"; ctx.veth_b ];
    ip [ "link"; "set"; ctx.veth_a; "netns"; ctx.ns_a ];
    ip [ "link"; "set"; ctx.veth_b; "netns"; ctx.ns_b ];
    ip [ "-n"; ctx.ns_a; "addr"; "add"; "10.77.0.1/24"; "dev"; ctx.veth_a ];
    ip [ "-n"; ctx.ns_b; "addr"; "add"; "10.77.0.2/24"; "dev"; ctx.veth_b ];
    ip [ "-n"; ctx.ns_a; "link"; "set"; "lo"; "up" ];
    ip [ "-n"; ctx.ns_b; "link"; "set"; "lo"; "up" ];
    ip [ "-n"; ctx.ns_a; "link"; "set"; ctx.veth_a; "up" ];
    ip [ "-n"; ctx.ns_b; "link"; "set"; ctx.veth_b; "up" ];
  ]
  |> List.iter (fun cmd ->
         match expect_success cmd with
         | Ok _ -> ()
         | Error message -> failwith message)

let cleanup_context ctx =
  ignore_result (ip [ "netns"; "delete"; ctx.ns_a ]);
  ignore_result (ip [ "netns"; "delete"; ctx.ns_b ])

let require_tools () =
  [
    ip [ "-Version" ];
    nft [ "--version" ];
    tc [ "-Version" ];
    invocation "ping" [ "-V" ];
    invocation "conntrack" [ "-V" ];
  ]
  |> List.iter (fun cmd ->
         match expect_success cmd with
         | Ok _ -> ()
         | Error message -> failwith ("missing or unusable E2E tool: " ^ message))

let apply_ruleset_logged ctx ruleset =
  with_temp_file "lpf-e2e-ruleset" (fun path ->
      write_file path ruleset;
      let invocation = netns_exec ctx.ns_b "nft" [ "-f"; path ] in
      let result = run_command invocation in
      (result, "intended-ruleset:\n" ^ ruleset ^ command_log "nft apply" invocation result))

let nft_cleanup_log ctx =
  let flush_invocation = netns_exec ctx.ns_b "nft" [ "flush"; "ruleset" ] in
  let flush_result = run_command flush_invocation in
  let list_invocation = netns_exec ctx.ns_b "nft" [ "list"; "ruleset" ] in
  let list_result = run_command list_invocation in
  command_log "nft remove all rules" flush_invocation flush_result
  ^ command_log "nft post-remove readback" list_invocation list_result

let nft_ruleset ~verdict ~log_prefix =
  let action = match verdict with `Accept -> "accept" | `Drop -> "drop" in
  let log =
    match log_prefix with
    | None -> ""
    | Some prefix -> Printf.sprintf " log prefix \"%s\" counter" prefix
  in
  String.concat "\n"
    [
      "flush ruleset";
      "table ip lpf_e2e {";
      "  chain input {";
      "    type filter hook input priority 0; policy accept;";
      "    ip saddr 10.77.0.1" ^ log ^ " " ^ action;
      "  }";
      "  chain output {";
      "    type filter hook output priority 0; policy accept;";
      "  }";
      "}";
      "";
    ]

let run_nft_accept ctx scenario =
  let apply, log = apply_ruleset_logged ctx (nft_ruleset ~verdict:`Accept ~log_prefix:None) in
  if apply.code <> 0 then Error (log ^ "nft apply failed for " ^ scenario.id)
  else
    let ping_invocation = netns_exec ctx.ns_a "ping" [ "-c"; "1"; "-W"; "1"; "10.77.0.2" ] in
    let ping = run_command ping_invocation in
    let list_invocation = netns_exec ctx.ns_b "nft" [ "list"; "ruleset" ] in
    let list_result = run_command list_invocation in
    let log =
      log ^ command_log "traffic probe" ping_invocation ping
      ^ command_log "nft applied readback" list_invocation list_result
      ^ nft_cleanup_log ctx
    in
    if ping.code = 0 then Ok (success_result log)
    else Error (log ^ Printf.sprintf "expected ping to pass for %s, got exit %d" scenario.id ping.code)

let run_nft_drop ctx scenario =
  let apply, log = apply_ruleset_logged ctx (nft_ruleset ~verdict:`Drop ~log_prefix:None) in
  if apply.code <> 0 then Error (log ^ "nft apply failed for " ^ scenario.id)
  else
    let ping_invocation = netns_exec ctx.ns_a "ping" [ "-c"; "1"; "-W"; "1"; "10.77.0.2" ] in
    let ping = run_command ping_invocation in
    let list_invocation = netns_exec ctx.ns_b "nft" [ "list"; "ruleset" ] in
    let list_result = run_command list_invocation in
    let log =
      log ^ command_log "traffic probe expected drop" ping_invocation ping
      ^ command_log "nft applied readback" list_invocation list_result
      ^ nft_cleanup_log ctx
    in
    if ping.code <> 0 then Ok (success_result log)
    else Error (log ^ Printf.sprintf "expected ping to be dropped for %s" scenario.id)

let run_nft_log ctx scenario =
  let prefix = Printf.sprintf "lpf-e2e-%03d " scenario.index in
  let apply, log = apply_ruleset_logged ctx (nft_ruleset ~verdict:`Accept ~log_prefix:(Some prefix)) in
  if apply.code <> 0 then Error (log ^ "nft apply failed for " ^ scenario.id)
  else (
    let ping_invocation = netns_exec ctx.ns_a "ping" [ "-c"; "1"; "-W"; "1"; "10.77.0.2" ] in
    let ping = run_command ping_invocation in
    if ping.code <> 0 then Error (log ^ Printf.sprintf "expected logged ping to pass, got exit %d" ping.code)
    else
      let list_invocation = netns_exec ctx.ns_b "nft" [ "list"; "ruleset" ] in
      let listed = run_command list_invocation in
      let log =
        log ^ command_log "traffic probe with nft log rule" ping_invocation ping
        ^ command_log "nft log rule readback" list_invocation listed
        ^ nft_cleanup_log ctx
      in
      if listed.code = 0 && String.contains listed.stdout 'l' && String.contains listed.stdout 'p' then
        Ok (success_result log)
      else Error (log ^ "nft ruleset did not contain expected logging rule for " ^ scenario.id))

let run_routing ctx scenario =
  let table = 1000 + scenario.index in
  let priority = 10000 + scenario.index in
  let mark = Printf.sprintf "0x%x" (0x1000 + scenario.index) in
  let delete_rule =
    ip [ "-n"; ctx.ns_a; "rule"; "delete"; "priority"; string_of_int priority; "fwmark"; mark; "table"; string_of_int table ]
  in
  let add_rule =
    ip [ "-n"; ctx.ns_a; "rule"; "add"; "priority"; string_of_int priority; "fwmark"; mark; "table"; string_of_int table ]
  in
  let add_route =
    ip [ "-n"; ctx.ns_a; "route"; "replace"; "default"; "via"; "10.77.0.2"; "dev"; ctx.veth_a; "table"; string_of_int table ]
  in
  let show_route = ip [ "-n"; ctx.ns_a; "route"; "show"; "table"; string_of_int table ] in
  let show_rule = ip [ "-n"; ctx.ns_a; "rule"; "show" ] in
  let flush_route = ip [ "-n"; ctx.ns_a; "route"; "flush"; "table"; string_of_int table ] in
  let before_delete = run_command delete_rule in
  let add_rule_result = run_command add_rule in
  let add_route_result = run_command add_route in
  let route_result = run_command show_route in
  let rule_result = run_command show_rule in
  let flush_route_result = run_command flush_route in
  let delete_rule_result = run_command delete_rule in
  let after_route_result = run_command show_route in
  let log =
    command_log "routing pre-clean rule" delete_rule before_delete
    ^ command_log "routing apply rule" add_rule add_rule_result
    ^ command_log "routing apply route" add_route add_route_result
    ^ command_log "routing route readback" show_route route_result
    ^ command_log "routing rule readback" show_rule rule_result
    ^ command_log "routing remove route table" flush_route flush_route_result
    ^ command_log "routing remove rule" delete_rule delete_rule_result
    ^ command_log "routing post-remove route readback" show_route after_route_result
  in
  if add_rule_result.code <> 0 then Error (log ^ "policy routing rule apply failed for " ^ scenario.id)
  else if add_route_result.code <> 0 then Error (log ^ "policy route apply failed for " ^ scenario.id)
  else if route_result.code = 0 && String.contains route_result.stdout 'd' && String.contains route_result.stdout '1' then
    Ok (success_result log)
  else Error (log ^ "policy route table did not render expected default route for " ^ scenario.id)

let run_tc ctx scenario =
  let rate = Printf.sprintf "%dmbit" ((scenario.index mod 40) + 1) in
  let del_qdisc = netns_exec ctx.ns_a "tc" [ "qdisc"; "del"; "dev"; ctx.veth_a; "root" ] in
  let add_qdisc =
    netns_exec ctx.ns_a "tc" [ "qdisc"; "add"; "dev"; ctx.veth_a; "root"; "handle"; "1:"; "htb"; "default"; "10" ]
  in
  let add_class =
    netns_exec ctx.ns_a "tc"
      [ "class"; "add"; "dev"; ctx.veth_a; "parent"; "1:"; "classid"; "1:10"; "htb"; "rate"; rate; "ceil"; rate ]
  in
  let show_class = netns_exec ctx.ns_a "tc" [ "class"; "show"; "dev"; ctx.veth_a ] in
  let show_qdisc = netns_exec ctx.ns_a "tc" [ "qdisc"; "show"; "dev"; ctx.veth_a ] in
  let before_delete = run_command del_qdisc in
  let add_qdisc_result = run_command add_qdisc in
  let add_class_result = run_command add_class in
  let class_result = run_command show_class in
  let qdisc_result = run_command show_qdisc in
  let cleanup_result = run_command del_qdisc in
  let after_qdisc_result = run_command show_qdisc in
  let log =
    command_log "tc pre-clean qdisc" del_qdisc before_delete
    ^ command_log "tc apply qdisc" add_qdisc add_qdisc_result
    ^ command_log "tc apply class" add_class add_class_result
    ^ command_log "tc class readback" show_class class_result
    ^ command_log "tc qdisc readback" show_qdisc qdisc_result
    ^ command_log "tc remove qdisc" del_qdisc cleanup_result
    ^ command_log "tc post-remove readback" show_qdisc after_qdisc_result
  in
  if add_qdisc_result.code <> 0 then Error (log ^ "tc qdisc apply failed for " ^ scenario.id)
  else if add_class_result.code <> 0 then Error (log ^ "tc class apply failed for " ^ scenario.id)
  else if class_result.code = 0 && String.contains class_result.stdout 'h' && String.contains class_result.stdout 'r' then
    Ok (success_result log)
  else Error (log ^ "tc class output did not contain expected HTB class for " ^ scenario.id)

let run_conntrack ctx _scenario =
  let ping_invocation = netns_exec ctx.ns_a "ping" [ "-c"; "1"; "-W"; "1"; "10.77.0.2" ] in
  let ping = run_command ping_invocation in
  let stats_invocation = netns_exec ctx.ns_a "conntrack" [ "-S" ] in
  let stats = run_command stats_invocation in
  let flush_invocation = netns_exec ctx.ns_a "conntrack" [ "-F" ] in
  let flush = run_command flush_invocation in
  let log =
    command_log "conntrack traffic probe" ping_invocation ping
    ^ command_log "conntrack stats readback" stats_invocation stats
    ^ command_log "conntrack cleanup flush" flush_invocation flush
  in
  if stats.code = 0 then Ok (success_result log)
  else Error (log ^ "conntrack stats failed")

let run_one ctx scenario =
  let started = Unix.gettimeofday () in
  let outcome =
    match scenario.family with
    | Nft_accept -> run_nft_accept ctx scenario
    | Nft_drop -> run_nft_drop ctx scenario
    | Nft_log -> run_nft_log ctx scenario
    | Routing -> run_routing ctx scenario
    | Traffic_shaping -> run_tc ctx scenario
    | Conntrack -> run_conntrack ctx scenario
  in
  let duration_ms = int_of_float ((Unix.gettimeofday () -. started) *. 1000.) in
  match outcome with
  | Ok process ->
      { scenario; status = Passed; stdout = process.stdout; stderr = process.stderr; duration_ms }
  | Error message -> { scenario; status = Failed message; stdout = ""; stderr = message; duration_ms }

let kernel_release () =
  let result = run_command (invocation "uname" [ "-r" ]) in
  if result.code = 0 then String.trim result.stdout else "unknown"

let summarize ~kernel_id ~kernel_release results =
  let passed =
    results
    |> List.filter (fun result -> match result.status with Passed -> true | Failed _ -> false)
    |> List.length
  in
  let failed = List.length results - passed in
  { kernel_id; kernel_release; scenario_count = List.length results; passed; failed; results }

let xml_escape text =
  let buffer = Buffer.create (String.length text) in
  String.iter
    (function
      | '&' -> Buffer.add_string buffer "&amp;"
      | '<' -> Buffer.add_string buffer "&lt;"
      | '>' -> Buffer.add_string buffer "&gt;"
      | '"' -> Buffer.add_string buffer "&quot;"
      | '\'' -> Buffer.add_string buffer "&apos;"
      | c -> Buffer.add_char buffer c)
    text;
  Buffer.contents buffer

let to_junit suite =
  let buffer = Buffer.create 16384 in
  Buffer.add_string buffer "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n";
  Buffer.add_string buffer
    (Printf.sprintf
       "<testsuite name=\"lpf-firecracker-e2e\" tests=\"%d\" failures=\"%d\" hostname=\"%s\">\n"
       suite.scenario_count suite.failed (xml_escape suite.kernel_id));
  List.iter
    (fun result ->
      Buffer.add_string buffer
        (Printf.sprintf "  <testcase classname=\"%s\" name=\"%s\" time=\"%.3f\">\n"
           (xml_escape (family_name result.scenario.family))
           (xml_escape result.scenario.id)
           (float_of_int result.duration_ms /. 1000.));
      (match result.status with
      | Passed -> ()
      | Failed message ->
          Buffer.add_string buffer
            (Printf.sprintf "    <failure message=\"%s\"><![CDATA[%s]]></failure>\n"
               (xml_escape message) message));
      Buffer.add_string buffer "  </testcase>\n")
    suite.results;
  Buffer.add_string buffer "</testsuite>\n";
  Buffer.contents buffer

let json_string = Json_util.string
let json_int value = string_of_int value
let status_name = function Passed -> "passed" | Failed _ -> "failed"

let allure_result suite result =
  let now = int_of_float (Unix.gettimeofday () *. 1000.) in
  let start = now - result.duration_ms in
  let labels =
    Json_util.list
      (fun (name, value) -> Json_util.field_object [ ("name", json_string name); ("value", json_string value) ])
      [
        ("suite", "lpf-firecracker-e2e");
        ("feature", family_name result.scenario.family);
        ("kernel", suite.kernel_id);
      ]
  in
  let parameters =
    Json_util.list
      (fun (name, value) -> Json_util.field_object [ ("name", json_string name); ("value", json_string value) ])
      [
        ("scenario_index", string_of_int result.scenario.index);
        ("kernel_release", suite.kernel_release);
      ]
  in
  let base_fields =
    [
      ("uuid", json_string result.scenario.id);
      ("name", json_string result.scenario.id);
      ("fullName", json_string result.scenario.description);
      ("status", json_string (status_name result.status));
      ("stage", json_string "finished");
      ("start", json_int start);
      ("stop", json_int now);
      ("labels", labels);
      ("parameters", parameters);
    ]
  in
  let fields =
    match result.status with
    | Passed -> base_fields
    | Failed message ->
        base_fields
        @ [
            ( "statusDetails",
              Json_util.field_object
                [
                  ("message", json_string message);
                  ("trace", json_string result.stderr);
                ] );
          ]
  in
  Json_util.field_object fields ^ "\n"

let evidence_manifest suite =
  Json_util.field_object
    [
      ("version", json_int 1);
      ("suite", json_string "lpf-firecracker-e2e");
      ("kernel_id", json_string suite.kernel_id);
      ("kernel_release", json_string suite.kernel_release);
      ("scenario_count", json_int suite.scenario_count);
      ("passed", json_int suite.passed);
      ("failed", json_int suite.failed);
      ( "families",
        Json_util.list json_string
          [
            family_name Nft_accept;
            family_name Nft_drop;
            family_name Nft_log;
            family_name Routing;
            family_name Traffic_shaping;
            family_name Conntrack;
          ] );
    ]
  ^ "\n"

let scenario_log_line result =
  Json_util.field_object
    [
      ("id", json_string result.scenario.id);
      ("family", json_string (family_name result.scenario.family));
      ("status", json_string (status_name result.status));
      ("duration_ms", json_int result.duration_ms);
      ("description", json_string result.scenario.description);
      ("stdout", json_string result.stdout);
      ("stderr", json_string result.stderr);
    ]
  ^ "\n"

let scenario_log suite = String.concat "" (List.map scenario_log_line suite.results)

let write_outputs (config : config) (suite : suite_result) =
  (match config.junit_path with Some path -> write_file path (to_junit suite) | None -> ());
  (match config.allure_dir with
  | None -> ()
  | Some dir ->
      ensure_dir dir;
      List.iter
        (fun result ->
          let path = Filename.concat dir (result.scenario.id ^ "-result.json") in
          write_file path (allure_result suite result))
        suite.results);
  match config.evidence_dir with
  | None -> ()
  | Some dir ->
      ensure_dir dir;
      write_file (Filename.concat dir "manifest.json") (evidence_manifest suite);
      write_file (Filename.concat dir "scenario-log.jsonl") (scenario_log suite)

let dry_run (config : config) =
  let kernel_release = kernel_release () in
  let kernel_id = match config.kernel_id with Some id -> id | None -> kernel_release in
  let results =
    scenario_catalog config.scenario_count
    |> List.map (fun scenario -> { scenario; status = Passed; stdout = "dry-run"; stderr = ""; duration_ms = 0 })
  in
  let suite = summarize ~kernel_id ~kernel_release results in
  write_outputs config suite;
  suite

let run (config : config) =
  validate_scenario_count config.scenario_count;
  if config.dry_run then dry_run config
  else (
    require_tools ();
    let kernel_release = kernel_release () in
    let kernel_id = Option.value config.kernel_id ~default:kernel_release in
    let ctx = make_context () in
    setup_context ctx;
    Fun.protect
      ~finally:(fun () -> cleanup_context ctx)
      (fun () ->
        let results = List.map (run_one ctx) (scenario_catalog config.scenario_count) in
        let suite = summarize ~kernel_id ~kernel_release results in
        write_outputs config suite;
        suite))
