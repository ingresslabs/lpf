type command = Add | Del | Check | Version

type ipam_config = {
  ipam_type : string;
  ipam_subnet : string option;
  ipam_routes : (string * string option) list;
}

type policy_config = {
  policy_mode : string;
  default_action : string;
  cluster_policy_ref : string option;
  log_dropped : bool;
  audit_mode : bool;
}

type network_config = {
  cni_version : string;
  name : string;
  cnitype : string;
  ipam : ipam_config option;
  policy : policy_config option;
  prev_result : string option;
}

type ip_result = {
  ip_address : string;
  gateway : string option;
  routes : (string * string option) list;
  dns_nameservers : string list;
}

(* ─── environment ─── *)

let getenv_default name default =
  match Sys.getenv_opt name with Some v -> v | None -> default

let trim s =
  let len = String.length s in
  let i = ref 0 in
  let j = ref (len - 1) in
  while
    !i < len && (s.[!i] = ' ' || s.[!i] = '\t' || s.[!i] = '\n' || s.[!i] = '\r')
  do
    incr i
  done;
  while
    !j >= !i && (s.[!j] = ' ' || s.[!j] = '\t' || s.[!j] = '\n' || s.[!j] = '\r')
  do
    decr j
  done;
  if !i > !j then "" else String.sub s !i (!j - !i + 1)

let opt_bind f opt = match opt with Some x -> f x | None -> None

(* ─── command execution ─── *)

let run_cmd cmd =
  let exit_code = Sys.command cmd in
  if exit_code = 0 then Ok ()
  else Error (Printf.sprintf "command failed (%d): %s" exit_code cmd)

let run_cmd_out cmd =
  let ic = Unix.open_process_in cmd in
  let buf = Buffer.create 256 in
  (try
     while true do
       Buffer.add_string buf (input_line ic);
       Buffer.add_char buf '\n'
     done
   with End_of_file -> ());
  match Unix.close_process_in ic with
  | Unix.WEXITED 0 -> Ok (trim (Buffer.contents buf))
  | Unix.WEXITED n -> Error (Printf.sprintf "command exited %d: %s" n cmd)
  | Unix.WSIGNALED n -> Error (Printf.sprintf "command killed %d: %s" n cmd)
  | Unix.WSTOPPED _ -> Error (Printf.sprintf "command stopped: %s" cmd)

(* ─── parsing ─── *)

let parse_command s =
  match String.lowercase_ascii (trim s) with
  | "add" -> Ok Add
  | "del" -> Ok Del
  | "check" -> Ok Check
  | "version" -> Ok Version
  | x -> Error (Printf.sprintf "unknown CNI command: %s" x)

let parse_ipam json =
  let open Json_parse in
  let obj = match json with Object o -> o | _ -> [] in
  let ipam_type =
    match List.assoc_opt "type" obj with
    | Some (String t) -> t
    | _ -> "host-local"
  in
  let ipam_subnet =
    match List.assoc_opt "subnet" obj with
    | Some (String s) -> Some s
    | _ -> None
  in
  let ipam_routes =
    match List.assoc_opt "routes" obj with
    | Some (Array items) ->
        List.filter_map
          (fun item ->
            match item with
            | Object fields -> (
                let dst =
                  List.assoc_opt "dst" fields |> opt_bind string_value
                in
                let gw = List.assoc_opt "gw" fields |> opt_bind string_value in
                match dst with Some d -> Some (d, gw) | None -> None)
            | _ -> None)
          items
    | _ -> []
  in
  { ipam_type; ipam_subnet; ipam_routes }

let parse_policy json =
  let open Json_parse in
  let obj = match json with Object o -> o | _ -> [] in
  {
    policy_mode =
      (match List.assoc_opt "mode" obj |> opt_bind string_value with
      | Some m -> m
      | None -> "auto");
    default_action =
      (match List.assoc_opt "defaultAction" obj |> opt_bind string_value with
      | Some a -> a
      | None -> "deny");
    cluster_policy_ref =
      List.assoc_opt "clusterPolicyRef" obj |> opt_bind string_value;
    log_dropped =
      (match List.assoc_opt "logDropped" obj |> opt_bind bool_value with
      | Some b -> b
      | None -> true);
    audit_mode =
      (match List.assoc_opt "auditMode" obj |> opt_bind bool_value with
      | Some b -> b
      | None -> false);
  }

let parse_network_config text =
  let open Json_parse in
  match parse text with
  | Error e -> Error (Printf.sprintf "JSON parse error: %s" e)
  | Ok json ->
      let obj = match json with Object o -> o | _ -> [] in
      let cni_version =
        match List.assoc_opt "cniVersion" obj |> opt_bind string_value with
        | Some v -> v
        | None -> "0.3.1"
      in
      let name =
        match List.assoc_opt "name" obj |> opt_bind string_value with
        | Some n -> n
        | None -> "lpf"
      in
      let cnitype =
        match List.assoc_opt "type" obj |> opt_bind string_value with
        | Some t -> t
        | None -> "lpf-cni"
      in
      let ipam =
        match List.assoc_opt "ipam" obj with
        | Some ipam_json -> Some (parse_ipam ipam_json)
        | None -> None
      in
      let policy =
        match List.assoc_opt "policy" obj with
        | Some p -> Some (parse_policy p)
        | None -> None
      in
      let prev_result = None in
      Ok { cni_version; name; cnitype; ipam; policy; prev_result }

(* ─── networking primitives ─── *)

let veth_name container_id ifname =
  let hash = Digest.to_hex (Digest.string container_id) in
  let short = String.sub hash 0 8 in
  ("lpfh" ^ short, ifname)

let create_veth_pair host_if container_if =
  run_cmd
    (Printf.sprintf "ip link add %s type veth peer name %s" host_if container_if)

let delete_veth host_if =
  run_cmd (Printf.sprintf "ip link delete %s 2>/dev/null" host_if)

let move_if_to_netns ifname netns =
  run_cmd (Printf.sprintf "ip link set %s netns %s" ifname netns)

let set_if_up ifname = run_cmd (Printf.sprintf "ip link set %s up" ifname)

let set_if_up_in_netns_by_path ifname netns_path =
  run_cmd
    (Printf.sprintf "nsenter --net=%s ip link set %s up" netns_path ifname)

let assign_ip ifname ip_addr netns_path =
  run_cmd
    (Printf.sprintf "nsenter --net=%s ip addr add %s dev %s" netns_path ip_addr
       ifname)

let add_route ifname dst gw netns_path =
  let gw_str = match gw with Some g -> " via " ^ g | None -> "" in
  let dev_str = " dev " ^ ifname in
  run_cmd
    (Printf.sprintf "nsenter --net=%s ip route add %s%s%s" netns_path dst gw_str
       dev_str)

let add_default_route ifname gw netns_path =
  match gw with
  | Some g -> add_route ifname "0.0.0.0/0" (Some g) netns_path
  | None -> add_route ifname "0.0.0.0/0" None netns_path

(* ─── IPAM delegation ─── *)

let call_ipam plugin_path ipam_config _container_id _ifname =
  let open Json_parse in
  let ipam_input =
    let ipam_obj =
      [ ("type", String ipam_config.ipam_type); ("name", String "lpf-ipam") ]
      @ (match ipam_config.ipam_subnet with
        | Some s -> [ ("subnet", String s) ]
        | None -> [])
      @
      if ipam_config.ipam_routes <> [] then
        [
          ( "routes",
            Array
              (List.map
                 (fun (dst, gw) ->
                   let fields =
                     [ ("dst", String dst) ]
                     @
                     match gw with Some g -> [ ("gw", String g) ] | None -> []
                   in
                   Object fields)
                 ipam_config.ipam_routes) );
        ]
      else []
    in
    string_of_json (Object ipam_obj)
  in
  let plugin = Filename.concat plugin_path ipam_config.ipam_type in
  if not (Sys.file_exists plugin) then
    Error (Printf.sprintf "IPAM plugin not found: %s" plugin)
  else
    let tmpfile = Filename.temp_file "lpf-ipam-input" ".json" in
    File_util.write_file tmpfile ipam_input;
    let cmd = Printf.sprintf "%s < %s" plugin tmpfile in
    match run_cmd_out cmd with
    | Ok output -> (
        Sys.remove tmpfile;
        match parse output with
        | Ok ipam_json -> (
            let obj = match ipam_json with Object o -> o | _ -> [] in
            let ips =
              match List.assoc_opt "ips" obj with
              | Some (Array items) ->
                  List.filter_map
                    (fun item ->
                      match item with
                      | Object fields -> (
                          let addr =
                            List.assoc_opt "address" fields
                            |> opt_bind string_value
                          in
                          let gw =
                            List.assoc_opt "gateway" fields
                            |> opt_bind string_value
                          in
                          match addr with
                          | Some a -> Some (a, gw)
                          | None -> None)
                      | _ -> None)
                    items
              | _ -> (
                  match List.assoc_opt "ip4" obj with
                  | Some (Object fields) -> (
                      let ip =
                        List.assoc_opt "ip" fields |> opt_bind string_value
                      in
                      let gw =
                        List.assoc_opt "gateway" fields |> opt_bind string_value
                      in
                      match ip with Some i -> [ (i, gw) ] | None -> [])
                  | _ -> [])
            in
            let routes =
              match List.assoc_opt "routes" obj with
              | Some (Array items) ->
                  List.filter_map
                    (fun item ->
                      match item with
                      | Object fields -> (
                          let dst =
                            List.assoc_opt "dst" fields |> opt_bind string_value
                          in
                          let gw =
                            List.assoc_opt "gw" fields |> opt_bind string_value
                          in
                          match dst with Some d -> Some (d, gw) | None -> None)
                      | _ -> None)
                    items
              | _ -> ipam_config.ipam_routes
            in
            let dns_servers =
              match List.assoc_opt "dns" obj with
              | Some (Object dns_fields) -> (
                  match List.assoc_opt "nameservers" dns_fields with
                  | Some (Array items) -> List.filter_map string_value items
                  | _ -> [])
              | _ -> []
            in
            match ips with
            | (ip_addr, gw) :: _ -> Ok (ip_addr, gw, routes, dns_servers)
            | [] -> Error "IPAM returned no IP addresses")
        | Error e -> Error (Printf.sprintf "IPAM parse error: %s" e))
    | Error e ->
        (try Sys.remove tmpfile with _ -> ());
        Error e

(* ─── BPF cgroup attachment ─── *)

let find_cgroup_path container_id =
  let pid_cmd = Printf.sprintf "pgrep -f %s | head -1" container_id in
  match run_cmd_out pid_cmd with
  | Ok pid_str -> (
      let pid = trim pid_str in
      if pid = "" then
        Error (Printf.sprintf "no process found for container %s" container_id)
      else
        let cgroup_cmd =
          Printf.sprintf
            "cat /proc/%s/cgroup 2>/dev/null | head -1 | cut -d: -f3" pid
        in
        match run_cmd_out cgroup_cmd with
        | Ok cgroup_rel ->
            let cgroup_rel_trimmed = trim cgroup_rel in
            let cgroup_path = "/sys/fs/cgroup" ^ cgroup_rel_trimmed in
            Ok cgroup_path
        | Error e -> Error (Printf.sprintf "cgroup lookup failed: %s" e))
  | Error _e -> (
      let netns_hint =
        Printf.sprintf
          "grep -l %s /proc/*/net/ns/net 2>/dev/null | head -1 | cut -d/ -f3"
          container_id
      in
      match run_cmd_out netns_hint with
      | Ok pid_str -> (
          let pid = trim pid_str in
          if pid = "" then
            Error
              (Printf.sprintf "cannot find cgroup for container %s" container_id)
          else
            let cgroup_cmd =
              Printf.sprintf
                "cat /proc/%s/cgroup 2>/dev/null | head -1 | cut -d: -f3" pid
            in
            match run_cmd_out cgroup_cmd with
            | Ok cgroup_rel ->
                let cgroup_path = "/sys/fs/cgroup" ^ trim cgroup_rel in
                Ok cgroup_path
            | Error e -> Error (Printf.sprintf "cgroup lookup failed: %s" e))
      | Error _ ->
          Error
            (Printf.sprintf "cannot find cgroup for container %s" container_id))

let attach_bpf cgroup_path _policy_mode =
  let bpffs = "/sys/fs/bpf/lpf" in
  let prog_ingress = Filename.concat bpffs "progs/cgroup_ingress" in
  let prog_egress = Filename.concat bpffs "progs/cgroup_egress" in
  if Sys.file_exists prog_ingress then
    ignore
      (run_cmd
         (Printf.sprintf
            "bpftool cgroup attach %s cgroup_skb ingress pinned %s 2>/dev/null"
            cgroup_path prog_ingress));
  if Sys.file_exists prog_egress then
    ignore
      (run_cmd
         (Printf.sprintf
            "bpftool cgroup attach %s cgroup_skb egress pinned %s 2>/dev/null"
            cgroup_path prog_egress))

let detach_bpf cgroup_path =
  let bpffs = "/sys/fs/bpf/lpf" in
  let prog_ingress = Filename.concat bpffs "progs/cgroup_ingress" in
  let prog_egress = Filename.concat bpffs "progs/cgroup_egress" in
  if Sys.file_exists prog_ingress then
    ignore
      (run_cmd
         (Printf.sprintf
            "bpftool cgroup detach %s cgroup_skb ingress pinned %s 2>/dev/null"
            cgroup_path prog_ingress));
  if Sys.file_exists prog_egress then
    ignore
      (run_cmd
         (Printf.sprintf
            "bpftool cgroup detach %s cgroup_skb egress pinned %s 2>/dev/null"
            cgroup_path prog_egress))

(* ─── ADD handler ─── *)

let handle_add cfg netns_path container_id ifname =
  let host_if, container_if = veth_name container_id ifname in
  match create_veth_pair host_if container_if with
  | Error e -> Error (Printf.sprintf "veth create: %s" e)
  | Ok () -> (
      match move_if_to_netns container_if netns_path with
      | Error e ->
          ignore (delete_veth host_if);
          Error (Printf.sprintf "netns move: %s" e)
      | Ok () -> (
          match set_if_up host_if with
          | Error e ->
              ignore (delete_veth host_if);
              Error (Printf.sprintf "host if up: %s" e)
          | Ok () -> (
              match set_if_up_in_netns_by_path container_if netns_path with
              | Error e ->
                  ignore (delete_veth host_if);
                  Error (Printf.sprintf "container if up: %s" e)
              | Ok () -> (
                  match cfg.ipam with
                  | Some ipam_cfg -> (
                      let cni_path = getenv_default "CNI_PATH" "/opt/cni/bin" in
                      match
                        call_ipam cni_path ipam_cfg container_id container_if
                      with
                      | Error e ->
                          ignore (delete_veth host_if);
                          Error (Printf.sprintf "IPAM: %s" e)
                      | Ok (ip_addr, gw, routes, dns_servers) -> (
                          let addrs = String.split_on_char '/' ip_addr in
                          let _ip = List.hd addrs in
                          match assign_ip container_if ip_addr netns_path with
                          | Error e ->
                              ignore (delete_veth host_if);
                              Error (Printf.sprintf "ip assign: %s" e)
                          | Ok () -> (
                              match
                                add_default_route container_if gw netns_path
                              with
                              | Error e ->
                                  ignore (delete_veth host_if);
                                  Error (Printf.sprintf "default route: %s" e)
                              | Ok () -> (
                                  let rec add_routes = function
                                    | [] -> Ok ()
                                    | (dst, dst_gw) :: rest -> (
                                        match
                                          add_route container_if dst dst_gw
                                            netns_path
                                        with
                                        | Error e ->
                                            Error
                                              (Printf.sprintf "route %s: %s" dst
                                                 e)
                                        | Ok () -> add_routes rest)
                                  in
                                  match add_routes routes with
                                  | Error e ->
                                      ignore (delete_veth host_if);
                                      Error e
                                  | Ok () -> (
                                      match cfg.policy with
                                      | Some _policy -> (
                                          match
                                            find_cgroup_path container_id
                                          with
                                          | Ok cg_path ->
                                              attach_bpf cg_path "auto";
                                              Ok
                                                {
                                                  ip_address = ip_addr;
                                                  gateway = gw;
                                                  routes;
                                                  dns_nameservers = dns_servers;
                                                }
                                          | Error _ ->
                                              Ok
                                                {
                                                  ip_address = ip_addr;
                                                  gateway = gw;
                                                  routes;
                                                  dns_nameservers = dns_servers;
                                                })
                                      | None ->
                                          Ok
                                            {
                                              ip_address = ip_addr;
                                              gateway = gw;
                                              routes;
                                              dns_nameservers = dns_servers;
                                            })))))
                  | None ->
                      Ok
                        {
                          ip_address = "";
                          gateway = None;
                          routes = [];
                          dns_nameservers = [];
                        }))))

(* ─── DEL handler ─── *)

let handle_del cfg _netns_path container_id ifname =
  let host_if, _container_if = veth_name container_id ifname in
  (match cfg.policy with
  | Some _ -> (
      match find_cgroup_path container_id with
      | Ok cg_path -> detach_bpf cg_path
      | Error _ -> ())
  | None -> ());
  (match cfg.ipam with
  | Some _ipam_cfg ->
      ignore
        (run_cmd (Printf.sprintf "ip addr flush dev %s 2>/dev/null" host_if))
  | None -> ());
  ignore (delete_veth host_if);
  Ok ()

(* ─── CHECK handler ─── *)

let handle_check cfg _netns_path container_id ifname =
  let host_if, _container_if = veth_name container_id ifname in
  match run_cmd_out (Printf.sprintf "ip link show %s 2>/dev/null" host_if) with
  | Error _ -> Error (Printf.sprintf "veth %s does not exist" host_if)
  | Ok _ -> (
      match cfg.policy with
      | Some _ -> (
          match find_cgroup_path container_id with
          | Ok _ -> Ok ()
          | Error e -> Error e)
      | None -> Ok ())

(* ─── VERSION ─── *)

let handle_version () =
  let version_json =
    Json_parse.string_of_json
      (Json_parse.Object
         [
           ("cniVersion", Json_parse.String "1.0.0");
           ( "supportedVersions",
             Json_parse.Array
               [
                 Json_parse.String "1.0.0";
                 Json_parse.String "0.4.0";
                 Json_parse.String "0.3.1";
               ] );
         ])
  in
  Printf.printf "%s\n%!" version_json

(* ─── result output ─── *)

let result_to_json result =
  let open Json_parse in
  let ips =
    Array
      [
        Object
          [
            ("address", String result.ip_address);
            ( "gateway",
              match result.gateway with Some g -> String g | None -> Null );
            ("interface", String "eth0");
          ];
      ]
  in
  let routes =
    Array
      (List.map
         (fun (dst, gw) ->
           let fields = [ ("dst", String dst) ] in
           let fields =
             match gw with
             | Some g -> ("gw", String g) :: fields
             | None -> fields
           in
           Object fields)
         result.routes)
  in
  let dns =
    Object
      [
        ( "nameservers",
          Array (List.map (fun s -> String s) result.dns_nameservers) );
      ]
  in
  string_of_json
    (Object
       [
         ("cniVersion", String "1.0.0");
         ("ips", ips);
         ("routes", routes);
         ("dns", dns);
       ])

let error_result code msg =
  let open Json_parse in
  string_of_json
    (Object
       [
         ("cniVersion", String "1.0.0");
         ("code", Number (float_of_int code));
         ("msg", String msg);
         ("details", String "");
       ])
