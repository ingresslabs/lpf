let () =
  let require condition message = if not condition then failwith message in
  let contains s sub =
    try
      ignore (Str.search_forward (Str.regexp_string sub) s 0);
      true
    with Not_found -> false
  in

  (* ─── JSON parser tests ─── *)
  let open Lpf.Json_parse in
  let t1 = parse "42" in
  require (match t1 with Ok (Number 42.) -> true | _ -> false) "parse int";

  let t2 = parse "3.14" in
  require (match t2 with Ok (Number 3.14) -> true | _ -> false) "parse float";

  let t3 = parse "\"hello\"" in
  require
    (match t3 with Ok (String "hello") -> true | _ -> false)
    "parse string";

  let t4 = parse "\"hello\\nworld\"" in
  require
    (match t4 with Ok (String "hello\nworld") -> true | _ -> false)
    "parse string with escape";

  let t5 = parse "true" in
  require (match t5 with Ok (Bool true) -> true | _ -> false) "parse true";

  let t6 = parse "false" in
  require (match t6 with Ok (Bool false) -> true | _ -> false) "parse false";

  let t7 = parse "null" in
  require (match t7 with Ok Null -> true | _ -> false) "parse null";

  let t8 = parse "[]" in
  require
    (match t8 with Ok (Array []) -> true | _ -> false)
    "parse empty array";

  let t9 = parse "[1, \"two\", true]" in
  require
    (match t9 with
    | Ok (Array [ Number 1.; String "two"; Bool true ]) -> true
    | _ -> false)
    "parse mixed array";

  let t10 = parse "{}" in
  require
    (match t10 with Ok (Object []) -> true | _ -> false)
    "parse empty object";

  let t11 = parse "{\"key\": \"value\"}" in
  require
    (match t11 with
    | Ok (Object [ ("key", String "value") ]) -> true
    | _ -> false)
    "parse simple object";

  let t12 = parse "{\"a\": 1, \"b\": true}" in
  require
    (match t12 with
    | Ok (Object [ ("a", Number 1.); ("b", Bool true) ]) -> true
    | _ -> false)
    "parse multi-field object";

  let t13 = parse "{\"nested\": {\"key\": [1, 2]}}" in
  require
    (match t13 with
    | Ok
        (Object
          [ ("nested", Object [ ("key", Array [ Number 1.; Number 2. ]) ]) ]) ->
        true
    | _ -> false)
    "parse nested";

  let t14 = parse "invalid" in
  require
    (match t14 with Error _ -> true | _ -> false)
    "parse error on invalid";

  let t15 = parse "{\"x\": 1}" in
  require
    (match t15 with Ok (Object [ ("x", Number 1.) ]) -> true | _ -> false)
    "parse simple object ok";

  let t16 = string_value (String "hello") in
  require (t16 = Some "hello") "string_value extract";

  let t17 = bool_value (Bool true) in
  require (t17 = Some true) "bool_value extract";

  let t18 = int_value (Number 42.) in
  require (t18 = Some 42) "int_value extract";

  let t19 = float_value (Number (float_of_int 42)) in
  require (t19 = Some (float_of_int 42)) "float_value extract";

  let t20 =
    lookup
      (fst (match t13 with Ok v -> (v, ()) | _ -> failwith "no"))
      [ "nested"; "key" ]
  in
  require
    (match t20 with
    | Some (Array [ Number 1.; Number 2. ]) -> true
    | _ -> false)
    "lookup nested";

  let t21 =
    lookup
      (fst (match t13 with Ok v -> (v, ()) | _ -> failwith "no"))
      [ "missing" ]
  in
  require (t21 = None) "lookup missing";

  Printf.printf "json_parse tests passed\n";

  (* ─── CNI config parsing tests ─── *)
  let open Lpf.Cni in
  let cfg_json =
    "{\"cniVersion\":\"1.0.0\",\"name\":\"lpf\",\"type\":\"lpf-cni\",\"ipam\":{\"type\":\"host-local\",\"subnet\":\"10.42.0.0/16\"}}"
  in
  let cfg = parse_network_config cfg_json in
  require
    (match cfg with Ok c -> c.cni_version = "1.0.0" | _ -> false)
    "CNI parse: cniVersion";
  require
    (match cfg with Ok c -> c.name = "lpf" | _ -> false)
    "CNI parse: name";
  require
    (match cfg with Ok c -> c.cnitype = "lpf-cni" | _ -> false)
    "CNI parse: type";
  require
    (match cfg with
    | Ok c -> (
        match c.ipam with Some ip -> ip.ipam_type = "host-local" | _ -> false)
    | _ -> false)
    "CNI parse: ipam type";

  let cmd_add = parse_command "ADD" in
  require (cmd_add = Ok Add) "CNI parse command: ADD";

  let cmd_del = parse_command "DEL" in
  require (cmd_del = Ok Del) "CNI parse command: DEL";

  let cmd_check = parse_command "CHECK" in
  require (cmd_check = Ok Check) "CNI parse command: CHECK";

  let cmd_version = parse_command "VERSION" in
  require (cmd_version = Ok Version) "CNI parse command: VERSION";

  let cmd_unknown = parse_command "UNKNOWN" in
  require
    (match cmd_unknown with Error _ -> true | _ -> false)
    "CNI parse command: unknown";

  let result =
    {
      ip_address = "10.42.0.5/24";
      gateway = Some "10.42.0.1";
      routes = [ ("0.0.0.0/0", Some "10.42.0.1") ];
      dns_nameservers = [ "10.43.0.10" ];
    }
  in
  let result_json = result_to_json result in
  require (contains result_json "10.42.0.5/24") "result_to_json contains ip";
  require (contains result_json "10.42.0.1") "result_to_json contains gateway";
  require (contains result_json "\"interfaces\"") "result_to_json has interfaces";
  require
    (contains result_json "\"interface\": 0")
    "result_to_json uses numeric interface index";
  require
    (not (contains result_json "\"interface\": \"eth0\""))
    "result_to_json does not use string interface name in ip";

  let err = error_result 7 "test error" in
  require (contains err "7") "error_result contains code";
  require (contains err "test error") "error_result contains message";

  Printf.printf "cni tests passed\n"
