let obj_fields = function
  | Json_parse.Object fields -> fields
  | _ -> []

let field_string name fields =
  match List.assoc_opt name fields with
  | Some v -> Json_parse.string_value v
  | None -> None

let field_list name fields =
  match List.assoc_opt name fields with
  | Some (Json_parse.Array items) -> items
  | _ -> []

let safe_name s =
  let buf = Buffer.create (String.length s) in
  String.iter (fun c ->
    if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c = '-' || c = '_' then
      Buffer.add_char buf c
    else
      Buffer.add_char buf '-') s;
  Buffer.contents buf

let translate_one_group group_json =
  let fields = obj_fields group_json in
  let name = match field_string "Name" fields with Some n -> n | None -> "unnamed" in
  let networks = field_list "Networks" fields in

  let rules = ref [] in

  List.iter (fun net_json ->
    let net_fields = obj_fields net_json in
    let mode = match field_string "Mode" net_fields with Some m -> m | None -> "bridge" in
    let ports = field_list "DynamicPorts" net_fields @ field_list "ReservedPorts" net_fields in

    if mode = "bridge" then begin
      List.iter (fun port_json ->
        let port_fields = obj_fields port_json in
        let port_num = match field_string "Value" port_fields with
          | Some s -> begin match int_of_string_opt s with Some n -> n | None -> 0 end
          | None -> 0
        in
        if port_num > 0 then
          rules := Printf.sprintf "  pass in on eth0 proto tcp from any to any port %d" port_num :: !rules
      ) ports;

      rules := "  pass out on eth0 to any port {443,53} keep state" :: !rules
    end
  ) networks;

  if !rules = [] then
    ""
  else
    let anchor_name = safe_name ("nomad-" ^ name) in
    Printf.sprintf "anchor %s {\n%s\n}\n" anchor_name (String.concat "\n" !rules)

let translate_nomad_network json =
  try
    let job_fields = obj_fields json in
    let job_name = match field_string "Name" job_fields with Some n -> n | None -> "unnamed" in
    let groups = field_list "TaskGroups" job_fields in
    let policy_text = String.concat "\n" (List.map translate_one_group groups) in
    let header = Printf.sprintf "# Generated from Nomad job: %s\n" job_name in
    Ok (header ^ policy_text)
  with
  | Failure msg -> Error (Printf.sprintf "translation error: %s" msg)
  | _ -> Error "translation error"
