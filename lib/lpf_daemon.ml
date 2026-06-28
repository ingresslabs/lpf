type config = {
  policy_path : string;
  cni_config_path : string;
  host_cni_bin_dir : string;
  host_cni_net_dir : string;
  cni_binary_source : string;
  bpf_object : string option;
  poll_interval : float;
  listen_address : string;
  port : int;
  install_cni : bool;
  kube_api_watch : bool;
  kube_api_server : string;
  kube_api_token_path : string;
  kube_api_ca_path : string;
}

type status = {
  started_at : float;
  mutable ready : bool;
  mutable last_reload_at : float option;
  mutable last_policy_hash : string option;
  mutable last_error : string option;
  mutable reloads : int;
  mutable failures : int;
}

let env name default =
  match Sys.getenv_opt name with
  | Some value when String.trim value <> "" -> String.trim value
  | _ -> default

let env_bool name default =
  match Sys.getenv_opt name with
  | Some value -> (
      match String.lowercase_ascii (String.trim value) with
      | "1" | "true" | "yes" | "on" -> true
      | "0" | "false" | "no" | "off" -> false
      | _ -> default)
  | None -> default

let env_float name default =
  match Sys.getenv_opt name with
  | Some value -> (
      match float_of_string_opt (String.trim value) with
      | Some f when f > 0. -> f
      | _ -> default)
  | None -> default

let env_int name default =
  match Sys.getenv_opt name with
  | Some value -> (
      match int_of_string_opt (String.trim value) with
      | Some i when i > 0 -> i
      | _ -> default)
  | None -> default

let default_kube_api_server () =
  match Sys.getenv_opt "LPF_DAEMON_KUBE_API_SERVER" with
  | Some value when String.trim value <> "" -> String.trim value
  | _ ->
      let host = env "KUBERNETES_SERVICE_HOST" "kubernetes.default.svc" in
      let port =
        env "KUBERNETES_SERVICE_PORT_HTTPS"
          (env "KUBERNETES_SERVICE_PORT" "443")
      in
      "https://" ^ host ^ ":" ^ port

let default_config () =
  let bpf_object =
    match Sys.getenv_opt "LPF_BPF_OBJECT" with
    | Some value when String.trim value <> "" -> Some (String.trim value)
    | _ -> Some (env "LPF_DAEMON_BPF_OBJECT" "/opt/lpf/bpf/lpf_kern.o")
  in
  {
    policy_path = env "LPF_DAEMON_POLICY_PATH" "/etc/lpf/policy/policy.lpf";
    cni_config_path =
      env "LPF_DAEMON_CNI_CONFIG_PATH" "/etc/lpf/cni/10-lpf.conflist";
    host_cni_bin_dir = env "LPF_DAEMON_HOST_CNI_BIN_DIR" "/host/opt/cni/bin";
    host_cni_net_dir = env "LPF_DAEMON_HOST_CNI_NET_DIR" "/host/etc/cni/net.d";
    cni_binary_source =
      env "LPF_DAEMON_CNI_BINARY_SOURCE" "/opt/cni/bin/lpf-cni";
    bpf_object;
    poll_interval = env_float "LPF_DAEMON_POLL_INTERVAL_SECONDS" 2.;
    listen_address = env "LPF_DAEMON_LISTEN_ADDRESS" "0.0.0.0";
    port = env_int "LPF_DAEMON_PORT" 9999;
    install_cni = env_bool "LPF_DAEMON_INSTALL_CNI" true;
    kube_api_watch = env_bool "LPF_DAEMON_KUBE_API_WATCH" false;
    kube_api_server = default_kube_api_server ();
    kube_api_token_path =
      env "LPF_DAEMON_KUBE_TOKEN_PATH"
        "/var/run/secrets/kubernetes.io/serviceaccount/token";
    kube_api_ca_path =
      env "LPF_DAEMON_KUBE_CA_PATH"
        "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt";
  }

let create_status () =
  {
    started_at = Unix.gettimeofday ();
    ready = false;
    last_reload_at = None;
    last_policy_hash = None;
    last_error = None;
    reloads = 0;
    failures = 0;
  }

let policy_hash text = Digest.to_hex (Digest.string text)

let read_file_result path =
  try Ok (File_util.read_file path) with exn -> Error (Printexc.to_string exn)

let read_all_channel ic =
  let buf = Buffer.create 4096 in
  (try
     while true do
       Buffer.add_string buf (input_line ic);
       Buffer.add_char buf '\n'
     done
   with End_of_file -> ());
  Buffer.contents buf

let run_capture prog args =
  try
    let argv = Array.of_list (prog :: args) in
    let ic = Unix.open_process_args_in prog argv in
    let output = read_all_channel ic in
    match Unix.close_process_in ic with
    | Unix.WEXITED 0 -> Ok output
    | Unix.WEXITED code ->
        Error (Printf.sprintf "%s exited %d: %s" prog code (String.trim output))
    | Unix.WSIGNALED signal ->
        Error (Printf.sprintf "%s killed by signal %d" prog signal)
    | Unix.WSTOPPED signal ->
        Error (Printf.sprintf "%s stopped by signal %d" prog signal)
  with exn -> Error (Printexc.to_string exn)

let with_kube_auth_header token f =
  try
    let path = Filename.temp_file "lpf-kube-auth-" ".header" in
    let oc =
      open_out_gen
        [ Open_wronly; Open_creat; Open_trunc; Open_binary ]
        0o600 path
    in
    Fun.protect
      ~finally:(fun () -> close_out_noerr oc)
      (fun () ->
        output_string oc ("Authorization: Bearer " ^ String.trim token ^ "\n"));
    Fun.protect
      ~finally:(fun () -> try Sys.remove path with Sys_error _ -> ())
      (fun () -> f path)
  with exn -> Error (Printexc.to_string exn)

let kube_get cfg path =
  match read_file_result cfg.kube_api_token_path with
  | Error error -> Error (Printf.sprintf "read service account token: %s" error)
  | Ok token ->
      let ca_args =
        if Sys.file_exists cfg.kube_api_ca_path then
          [ "--cacert"; cfg.kube_api_ca_path ]
        else [ "-k" ]
      in
      let url = cfg.kube_api_server ^ path in
      with_kube_auth_header token (fun header_path ->
          run_capture "curl"
            ([ "-fsS"; "--max-time"; "10" ]
            @ ca_args
            @ [ "-H"; "@" ^ header_path; "-H"; "Accept: application/json"; url ]
            ))

let json_fields = function Json_parse.Object fields -> fields | _ -> []
let json_field name fields = List.assoc_opt name fields

let json_field_string name fields =
  match json_field name fields with
  | Some value -> Json_parse.string_value value
  | None -> None

let json_field_int name fields =
  match json_field name fields with
  | Some (Json_parse.Number value) -> Some (int_of_float value)
  | Some (Json_parse.String value) -> int_of_string_opt value
  | _ -> None

let json_field_obj name fields =
  match json_field name fields with
  | Some (Json_parse.Object fields) -> fields
  | _ -> []

let items_from_list_json = function
  | Json_parse.Object fields -> (
      match json_field "items" fields with
      | Some (Json_parse.Array items) -> items
      | _ -> [])
  | _ -> []

let copy_file ~src ~dst =
  match read_file_result src with
  | Error error -> Error (Printf.sprintf "read %s: %s" src error)
  | Ok content -> (
      try
        File_util.ensure_dir ~strict:false (Filename.dirname dst);
        File_util.write_file dst content;
        Unix.chmod dst 0o755;
        Ok ()
      with exn ->
        Error (Printf.sprintf "write %s: %s" dst (Printexc.to_string exn)))

let install_cni_files cfg =
  if not cfg.install_cni then Ok ()
  else
    let dst_bin = Filename.concat cfg.host_cni_bin_dir "lpf-cni" in
    let dst_conf = Filename.concat cfg.host_cni_net_dir "10-lpf.conflist" in
    match copy_file ~src:cfg.cni_binary_source ~dst:dst_bin with
    | Error error -> Error error
    | Ok () -> (
        match read_file_result cfg.cni_config_path with
        | Error error ->
            Error (Printf.sprintf "read %s: %s" cfg.cni_config_path error)
        | Ok content -> (
            try
              File_util.ensure_dir ~strict:false cfg.host_cni_net_dir;
              File_util.write_file dst_conf content;
              Ok ()
            with exn ->
              Error
                (Printf.sprintf "write %s: %s" dst_conf (Printexc.to_string exn))
            ))

let diagnostic_text diagnostics =
  diagnostics |> List.map Policy.diagnostic_to_string |> String.concat "\n"

let has_prefix ~prefix text =
  let prefix_len = String.length prefix in
  String.length text >= prefix_len && String.sub text 0 prefix_len = prefix

let strip_default_lines policy =
  policy |> String.split_on_char '\n'
  |> List.filter (fun line ->
         let line = String.trim line in
         not (has_prefix ~prefix:"set default " line))
  |> String.concat "\n" |> String.trim

let comment_block title text =
  let lines =
    if String.trim text = "" then [] else String.split_on_char '\n' text
  in
  "# " ^ title ^ "\n"
  ^ String.concat "\n" (List.map (fun line -> "# " ^ line) lines)

let default_action_of_string value =
  match String.lowercase_ascii (String.trim value) with
  | "pass" | "allow" | "accept" -> Some "pass"
  | "deny" | "block" | "drop" -> Some "deny"
  | _ -> None

let item_key item =
  let fields = json_fields item in
  let metadata = json_field_obj "metadata" fields in
  let namespace =
    Option.value (json_field_string "namespace" metadata) ~default:""
  in
  let name =
    Option.value (json_field_string "name" metadata) ~default:"unnamed"
  in
  if namespace = "" then name else namespace ^ "/" ^ name

let item_priority item =
  let spec = json_field_obj "spec" (json_fields item) in
  Option.value (json_field_int "priority" spec) ~default:1000

let cluster_default_action cluster_policies =
  let sorted =
    List.sort
      (fun a b ->
        let by_priority = compare (item_priority a) (item_priority b) in
        if by_priority <> 0 then by_priority
        else String.compare (item_key a) (item_key b))
      cluster_policies
  in
  let rec loop = function
    | [] -> "deny"
    | item :: rest -> (
        let spec = json_field_obj "spec" (json_fields item) in
        match json_field_string "defaultAction" spec with
        | Some value -> (
            match default_action_of_string value with
            | Some action -> action
            | None -> loop rest)
        | None -> loop rest)
  in
  loop sorted

type policy_fragment = {
  fragment_kind : string;
  fragment_key : string;
  fragment_priority : int;
  fragment_policy : string;
}

let policy_fragment_of_item kind item =
  let spec = json_field_obj "spec" (json_fields item) in
  match json_field_string "policy" spec with
  | None -> None
  | Some policy ->
      let policy = strip_default_lines policy in
      if policy = "" then None
      else
        Some
          {
            fragment_kind = kind;
            fragment_key = item_key item;
            fragment_priority = item_priority item;
            fragment_policy = policy;
          }

let compare_fragment a b =
  let by_priority = compare a.fragment_priority b.fragment_priority in
  if by_priority <> 0 then by_priority
  else
    let by_kind = String.compare a.fragment_kind b.fragment_kind in
    if by_kind <> 0 then by_kind
    else String.compare a.fragment_key b.fragment_key

let render_fragment fragment =
  Printf.sprintf "# %s %s priority=%d\n%s" fragment.fragment_kind
    fragment.fragment_key fragment.fragment_priority fragment.fragment_policy

let effective_policy_of_kubernetes_items ~cluster_policies ~namespaced_policies
    ~staged_policies ~network_policies =
  let default_action = cluster_default_action cluster_policies in
  let enforced_fragments =
    List.filter_map (policy_fragment_of_item "ClusterPolicy") cluster_policies
    @ List.filter_map
        (policy_fragment_of_item "NamespacedPolicy")
        namespaced_policies
    |> List.sort compare_fragment
  in
  let staged_fragments =
    staged_policies
    |> List.filter_map (policy_fragment_of_item "StagedPolicy")
    |> List.sort compare_fragment
  in
  match
    Network_policy_translate.translate_network_policies network_policies
  with
  | Error error -> Error ("translate NetworkPolicy: " ^ error)
  | Ok network_policy_text ->
      let staged_text =
        staged_fragments
        |> List.map (fun fragment ->
               comment_block
                 (Printf.sprintf "staged %s priority=%d (not enforced)"
                    fragment.fragment_key fragment.fragment_priority)
                 fragment.fragment_policy)
        |> String.concat "\n\n"
      in
      let sections =
        [
          "set default " ^ default_action;
          "interface eth0 = \"eth0\"";
          "# generated by lpf-daemon kubernetes api watcher";
          String.concat "\n\n" (List.map render_fragment enforced_fragments);
          String.trim network_policy_text;
          staged_text;
        ]
        |> List.map String.trim
        |> List.filter (fun section -> section <> "")
      in
      Ok (String.concat "\n\n" sections ^ "\n")

let parse_json_list label text =
  match Json_parse.parse text with
  | Error error -> Error (Printf.sprintf "parse %s: %s" label error)
  | Ok json -> Ok (items_from_list_json json)

let effective_policy_of_kubernetes_json ~cluster_policies ~namespaced_policies
    ~staged_policies ~network_policies =
  match parse_json_list "ClusterPolicyList" cluster_policies with
  | Error error -> Error error
  | Ok cluster_policies -> (
      match parse_json_list "NamespacedPolicyList" namespaced_policies with
      | Error error -> Error error
      | Ok namespaced_policies -> (
          match parse_json_list "StagedPolicyList" staged_policies with
          | Error error -> Error error
          | Ok staged_policies -> (
              match parse_json_list "NetworkPolicyList" network_policies with
              | Error error -> Error error
              | Ok network_policies ->
                  effective_policy_of_kubernetes_items ~cluster_policies
                    ~namespaced_policies ~staged_policies ~network_policies)))

let read_kubernetes_effective_policy cfg =
  let get label path =
    match kube_get cfg path with
    | Error error -> Error (Printf.sprintf "get %s: %s" label error)
    | Ok text -> parse_json_list label text
  in
  match
    get "ClusterPolicyList"
      "/apis/policy.ingresslabs.com/v1alpha1/clusterpolicies"
  with
  | Error error -> Error error
  | Ok cluster_policies -> (
      match
        get "NamespacedPolicyList"
          "/apis/policy.ingresslabs.com/v1alpha1/namespacedpolicies"
      with
      | Error error -> Error error
      | Ok namespaced_policies -> (
          match
            get "StagedPolicyList"
              "/apis/policy.ingresslabs.com/v1alpha1/stagedpolicies"
          with
          | Error error -> Error error
          | Ok staged_policies -> (
              match
                get "NetworkPolicyList"
                  "/apis/networking.k8s.io/v1/networkpolicies"
              with
              | Error error -> Error error
              | Ok network_policies ->
                  effective_policy_of_kubernetes_items ~cluster_policies
                    ~namespaced_policies ~staged_policies ~network_policies)))

let read_effective_policy cfg =
  if cfg.kube_api_watch then
    match read_kubernetes_effective_policy cfg with
    | Ok policy_text -> Ok ("kubernetes-api", policy_text)
    | Error error -> Error error
  else
    match read_file_result cfg.policy_path with
    | Ok policy_text -> Ok (cfg.policy_path, policy_text)
    | Error error -> Error (Printf.sprintf "read policy: %s" error)

let apply_policy_text cfg status ~source policy_text =
  let hash = policy_hash policy_text in
  (match cfg.bpf_object with
  | Some path when Sys.file_exists path -> Unix.putenv "LPF_BPF_OBJECT" path
  | _ -> ());
  match Pipeline.plan_policy_text ~file:source policy_text with
  | Error diagnostics ->
      let error = diagnostic_text diagnostics in
      status.ready <- false;
      status.failures <- status.failures + 1;
      status.last_error <- Some error;
      Error error
  | Ok (plan, _diagnostics) -> (
      let image = Ebpf.of_plan plan in
      match Ebpf.apply_with_runners Ebpf.default_runners image with
      | Ok () ->
          status.ready <- true;
          status.reloads <- status.reloads + 1;
          status.last_reload_at <- Some (Unix.gettimeofday ());
          status.last_policy_hash <- Some hash;
          status.last_error <- None;
          Ok ()
      | Error error ->
          let text = Nft.string_of_run_error error in
          status.ready <- false;
          status.failures <- status.failures + 1;
          status.last_error <- Some text;
          Error text)

let reload_policy cfg status =
  match read_effective_policy cfg with
  | Error error ->
      status.ready <- false;
      status.failures <- status.failures + 1;
      status.last_error <- Some error;
      Error error
  | Ok (source, policy_text) -> apply_policy_text cfg status ~source policy_text

let maybe_reload_policy cfg status =
  match read_effective_policy cfg with
  | Error error ->
      status.ready <- false;
      status.last_error <- Some error;
      Error error
  | Ok (source, policy_text) ->
      let hash = policy_hash policy_text in
      if status.last_policy_hash = Some hash && status.ready then Ok ()
      else apply_policy_text cfg status ~source policy_text

let metrics_text status =
  let ready = if status.ready then 1 else 0 in
  let last_reload =
    match status.last_reload_at with Some t -> t | None -> 0.
  in
  let hash =
    match status.last_policy_hash with Some h -> h | None -> "none"
  in
  String.concat "\n"
    [
      "# HELP lpf_daemon_ready 1 when the current policy is loaded.";
      "# TYPE lpf_daemon_ready gauge";
      Printf.sprintf "lpf_daemon_ready %d" ready;
      "# HELP lpf_daemon_reload_total Successful policy reloads.";
      "# TYPE lpf_daemon_reload_total counter";
      Printf.sprintf "lpf_daemon_reload_total %d" status.reloads;
      "# HELP lpf_daemon_reload_failure_total Failed policy reloads.";
      "# TYPE lpf_daemon_reload_failure_total counter";
      Printf.sprintf "lpf_daemon_reload_failure_total %d" status.failures;
      "# HELP lpf_daemon_last_reload_timestamp_seconds Last successful reload \
       time.";
      "# TYPE lpf_daemon_last_reload_timestamp_seconds gauge";
      Printf.sprintf "lpf_daemon_last_reload_timestamp_seconds %.0f" last_reload;
      "# HELP lpf_daemon_policy_info Active policy metadata.";
      "# TYPE lpf_daemon_policy_info gauge";
      Printf.sprintf "lpf_daemon_policy_info{hash=\"%s\"} 1" hash;
      "";
    ]

let route_response status path =
  match path with
  | "/livez" -> (200, "text/plain", "ok\n")
  | "/readyz" when status.ready -> (200, "text/plain", "ok\n")
  | "/readyz" ->
      let error = Option.value status.last_error ~default:"not ready" in
      (503, "text/plain", error ^ "\n")
  | "/metrics" -> (200, "text/plain; version=0.0.4", metrics_text status)
  | _ -> (404, "text/plain", "not found\n")

let http_status_text = function
  | 200 -> "OK"
  | 404 -> "Not Found"
  | 503 -> "Service Unavailable"
  | _ -> "OK"

let handle_client status fd =
  let ic = Unix.in_channel_of_descr fd in
  let oc = Unix.out_channel_of_descr fd in
  Fun.protect
    ~finally:(fun () -> close_out_noerr oc)
    (fun () ->
      let line =
        try input_line ic with End_of_file -> "GET /livez HTTP/1.0"
      in
      let path =
        match String.split_on_char ' ' line with
        | _method :: path :: _ -> path
        | _ -> "/livez"
      in
      let code, content_type, body = route_response status path in
      Printf.fprintf oc "HTTP/1.1 %d %s\r\n" code (http_status_text code);
      Printf.fprintf oc "Content-Type: %s\r\n" content_type;
      Printf.fprintf oc "Content-Length: %d\r\n" (String.length body);
      Printf.fprintf oc "Connection: close\r\n\r\n%s%!" body)

let sockaddr_of_config cfg =
  let inet_addr =
    if cfg.listen_address = "0.0.0.0" then Unix.inet_addr_any
    else Unix.inet_addr_of_string cfg.listen_address
  in
  Unix.ADDR_INET (inet_addr, cfg.port)

let run cfg =
  let status = create_status () in
  (match install_cni_files cfg with
  | Ok () -> ()
  | Error error ->
      status.last_error <- Some error;
      status.failures <- status.failures + 1;
      prerr_endline ("lpf-daemon install failed: " ^ error));
  (match reload_policy cfg status with
  | Ok () -> Printf.eprintf "lpf-daemon loaded initial policy\n%!"
  | Error error ->
      Printf.eprintf "lpf-daemon initial policy failed: %s\n%!" error);
  let socket = Unix.socket Unix.PF_INET Unix.SOCK_STREAM 0 in
  Unix.setsockopt socket Unix.SO_REUSEADDR true;
  Unix.bind socket (sockaddr_of_config cfg);
  Unix.listen socket 16;
  Printf.eprintf "lpf-daemon listening on %s:%d policy=%s\n%!"
    cfg.listen_address cfg.port cfg.policy_path;
  while true do
    let ready, _, _ = Unix.select [ socket ] [] [] cfg.poll_interval in
    if ready <> [] then (
      let client, _ = Unix.accept socket in
      try handle_client status client
      with exn ->
        close_out_noerr (Unix.out_channel_of_descr client);
        prerr_endline ("lpf-daemon http error: " ^ Printexc.to_string exn));
    match maybe_reload_policy cfg status with
    | Ok () -> ()
    | Error error -> prerr_endline ("lpf-daemon reload failed: " ^ error)
  done
