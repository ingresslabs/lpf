let json_string = Json_parse.string_value
let obj_fields = function Json_parse.Object fields -> fields | _ -> []

let field name fields =
  match List.assoc_opt name fields with Some v -> Some v | None -> None

let field_string name fields =
  match field name fields with Some v -> json_string v | None -> None

let field_list name fields =
  match field name fields with
  | Some (Json_parse.Array items) -> items
  | _ -> []

let field_obj name fields =
  match field name fields with Some (Json_parse.Object obj) -> obj | _ -> []

let safe_name s =
  let buf = Buffer.create (String.length s) in
  String.iter
    (fun c ->
      if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c = '-' || c = '_'
      then Buffer.add_char buf c
      else Buffer.add_char buf '-')
    s;
  Buffer.contents buf

let label_selector_to_set_name labels =
  let parts = List.map (fun (k, v) -> safe_name k ^ "-" ^ safe_name v) labels in
  "<" ^ String.concat "-" parts ^ ">"

let pod_selector_to_set_name json =
  let fields = obj_fields json in
  match field "matchLabels" fields with
  | Some (Json_parse.Object labels) ->
      let pairs =
        List.filter_map
          (fun (k, v) ->
            match v with Json_parse.String s -> Some (k, s) | _ -> None)
          labels
      in
      label_selector_to_set_name pairs
  | _ -> "<any>"

let namespace_selector_to_set_name json =
  let fields = obj_fields json in
  match field "matchLabels" fields with
  | Some (Json_parse.Object labels) ->
      let pairs =
        List.filter_map
          (fun (k, v) ->
            match v with Json_parse.String s -> Some (k, s) | _ -> None)
          labels
      in
      label_selector_to_set_name pairs
  | _ -> "<any>"

let protocol_string prot =
  match String.uppercase_ascii prot with
  | "TCP" -> "tcp"
  | "UDP" -> "udp"
  | "SCTP" -> "sctp"
  | _ -> "tcp"

let translate_ports ports =
  if ports = [] then [ (None, None) ]
  else
    List.filter_map
      (fun port_json ->
        let fields = obj_fields port_json in
        let port =
          match field "port" fields with
          | Some (Json_parse.Number f) -> Some (int_of_float f)
          | Some (Json_parse.String s) -> (
              match int_of_string_opt s with Some n -> Some n | None -> None)
          | _ -> None
        in
        let end_port =
          match field "endPort" fields with
          | Some (Json_parse.Number f) -> Some (int_of_float f)
          | _ -> None
        in
        let protocol =
          match field_string "protocol" fields with
          | Some p -> protocol_string p
          | None -> "tcp"
        in
        match (port, end_port) with
        | Some p, Some ep ->
            Some (Some protocol, Some (Printf.sprintf "%d:%d" p ep))
        | Some p, None -> Some (Some protocol, Some (string_of_int p))
        | None, _ -> Some (Some protocol, None))
      ports

let rule_proto = function Some protocol -> " proto " ^ protocol | None -> ""
let rule_port = function Some port -> " port " ^ port | None -> ""

let translate_peer_addr to_json =
  let fields = obj_fields to_json in
  let pod_sel = field "podSelector" fields in
  let ns_sel = field "namespaceSelector" fields in
  let ip_block = field "ipBlock" fields in
  match (pod_sel, ns_sel) with
  | Some ps, Some ns ->
      let _set_name = pod_selector_to_set_name ps in
      let ns_set_name = namespace_selector_to_set_name ns in
      Some ns_set_name
  | Some ps, None ->
      let set_name = pod_selector_to_set_name ps in
      Some set_name
  | None, Some ns ->
      let ns_set_name = namespace_selector_to_set_name ns in
      Some ns_set_name
  | None, None -> (
      match ip_block with
      | Some (Json_parse.Object ib_fields) -> (
          match field_string "cidr" ib_fields with
          | Some cidr ->
              let except = field_list "except" ib_fields in
              if except = [] then Some cidr else Some cidr
          | None -> Some "any")
      | _ -> Some "any")

let translate_ingress_rule rule_json =
  let fields = obj_fields rule_json in
  let froms = field_list "from" fields in
  let port_specs = translate_ports (field_list "ports" fields) in
  let sources =
    if froms = [] then [ "any" ]
    else List.filter_map translate_peer_addr froms
  in
  List.concat_map
    (fun source ->
      List.map
        (fun (protocol, port) ->
          "pass in on eth0" ^ rule_proto protocol ^ " from " ^ source
          ^ " to any" ^ rule_port port)
        port_specs)
    sources

let translate_egress_rule rule_json =
  let fields = obj_fields rule_json in
  let tos = field_list "to" fields in
  let port_specs = translate_ports (field_list "ports" fields) in
  let destinations =
    if tos = [] then [ "any" ]
    else List.filter_map translate_peer_addr tos
  in
  List.concat_map
    (fun destination ->
      List.map
        (fun (protocol, port) ->
          "pass out on eth0" ^ rule_proto protocol ^ " from any to "
          ^ destination ^ rule_port port ^ " keep state")
        port_specs)
    destinations

let translate_one_np np_json =
  let open Json_parse in
  let fields = obj_fields np_json in
  let metadata = field_obj "metadata" fields in
  let spec = field_obj "spec" fields in
  let name =
    match field_string "name" metadata with Some n -> n | None -> "unnamed"
  in
  let namespace =
    match field_string "namespace" metadata with
    | Some n -> n
    | None -> "default"
  in
  let anchor_name = safe_name (namespace ^ "-" ^ name) in

  let policy_types =
    match field "policyTypes" spec with
    | Some (Array types) -> List.filter_map string_value types
    | _ -> [ "Ingress" ]
  in

  let rules = ref [] in

  ((if List.mem "Ingress" policy_types then
      let ingress_rules = field_list "ingress" spec in
      List.iter
        (fun rule -> rules := !rules @ translate_ingress_rule rule)
        ingress_rules);

   if List.mem "Egress" policy_types then
     let egress_rules = field_list "egress" spec in
     List.iter
       (fun rule -> rules := !rules @ translate_egress_rule rule)
       egress_rules);

  let anchor_text =
    Printf.sprintf "anchor %s {\n" anchor_name
    ^ String.concat "\n" (List.map (fun r -> "  " ^ r) !rules)
    ^ "\n}\n"
  in
  anchor_text

let translate_network_policy json =
  try Ok (translate_one_np json) with
  | Failure msg -> Error (Printf.sprintf "translation error: %s" msg)
  | _ -> Error "translation error"

let translate_network_policies jsons =
  let results = List.map translate_one_np jsons in
  let policy_text = String.concat "\n" results in
  Ok policy_text
