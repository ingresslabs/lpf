type t = {
  schema : string;
  checksum : string;
  policy : Ir.t;
}

let schema = "lpf.plan.v1"

let json_string text =
  let buffer = Buffer.create (String.length text + 2) in
  Buffer.add_char buffer '"';
  String.iter
    (function
      | '"' -> Buffer.add_string buffer "\\\""
      | '\\' -> Buffer.add_string buffer "\\\\"
      | '\b' -> Buffer.add_string buffer "\\b"
      | '\012' -> Buffer.add_string buffer "\\f"
      | '\n' -> Buffer.add_string buffer "\\n"
      | '\r' -> Buffer.add_string buffer "\\r"
      | '\t' -> Buffer.add_string buffer "\\t"
      | character ->
          let code = Char.code character in
          if code < 0x20 then Buffer.add_string buffer (Printf.sprintf "\\u%04x" code)
          else Buffer.add_char buffer character)
    text;
  Buffer.add_char buffer '"';
  Buffer.contents buffer

let json_int value = string_of_int value
let json_list render values = "[" ^ String.concat "," (List.map render values) ^ "]"

let json_option render = function
  | None -> "null"
  | Some value -> render value

let json_object fields =
  "{"
  ^ String.concat ","
      (List.map (fun (name, value) -> json_string name ^ ":" ^ value) fields)
  ^ "}"

let span_json (span : Policy.span) =
  json_object
    [
      ("line", json_int span.line);
      ("column", json_int span.column);
      ("end_column", json_int span.end_column);
    ]

let add_span ~include_spans span fields =
  if include_spans then fields @ [ ("span", span_json span) ] else fields

let default_action_json = function
  | Policy.Default_pass -> json_string "pass"
  | Policy.Default_deny -> json_string "deny"

let action_json = function
  | Policy.Pass -> json_string "pass"
  | Policy.Block -> json_string "block"

let direction_json = function
  | Policy.In -> json_string "in"
  | Policy.Out -> json_string "out"

let protocol_json = function
  | Policy.Proto_any -> json_string "any"
  | Policy.Proto_named name -> json_string name

let log_json = function
  | Policy.Log_all -> json_string "all"
  | Policy.Log_matches -> json_string "matches"
  | Policy.Log_user -> json_string "user"

let interface_json ~include_spans (interface : Ir.interface_ref) =
  add_span ~include_spans interface.span
    [
      ("name", json_option json_string interface.name);
      ("device", json_string interface.device);
    ]
  |> json_object

let address_json = function
  | Ir.Any -> json_object [ ("kind", json_string "any") ]
  | Ir.Literal value ->
      json_object [ ("kind", json_string "literal"); ("value", json_string value) ]
  | Ir.Table name ->
      json_object [ ("kind", json_string "table"); ("name", json_string name) ]

let port_json = function
  | Ir.Port_any -> json_object [ ("kind", json_string "any") ]
  | Ir.Range (lower, upper) ->
      json_object
        [
          ("kind", json_string "range");
          ("lower", json_int lower);
          ("upper", json_int upper);
        ]

let table_json ~include_spans ~for_checksum (table : Ir.table) =
  let entries =
    if for_checksum then List.sort String.compare table.entries else table.entries
  in
  add_span ~include_spans table.span
    [
      ("name", json_string table.name);
      ("entries", json_list json_string entries);
    ]
  |> json_object

let queue_json ~include_spans (queue : Ir.queue) =
  add_span ~include_spans queue.span
    [
      ("name", json_string queue.name);
      ("interface", interface_json ~include_spans queue.interface);
      ("bandwidth", json_string queue.bandwidth);
      ("parent", json_option json_string queue.parent);
    ]
  |> json_object

let route_to_json ~include_spans (gateway, interface) =
  json_object
    [
      ("gateway", address_json gateway);
      ("interface", json_option (interface_json ~include_spans) interface);
    ]

let rule_json ~include_spans (rule : Ir.rule) =
  add_span ~include_spans rule.span
    [
      ("action", action_json rule.action);
      ("direction", json_option direction_json rule.direction);
      ("interface", json_option (interface_json ~include_spans) rule.interface);
      ("protocol", protocol_json rule.protocol);
      ("source", address_json rule.source);
      ("destination", address_json rule.destination);
      ("port", port_json rule.port);
      ("keep_state", if rule.keep_state then "true" else "false");
      ("log", json_option log_json rule.log);
      ("queue", json_option json_string rule.queue);
      ("route_to", json_option (route_to_json ~include_spans) rule.route_to);
    ]
  |> json_object

let nat_json ~include_spans (nat : Ir.nat) =
  add_span ~include_spans nat.span
    [
      ("interface", interface_json ~include_spans nat.interface);
      ("protocol", protocol_json nat.protocol);
      ("source", address_json nat.source);
      ("destination", address_json nat.destination);
      ("translation", address_json nat.translation);
    ]
  |> json_object

let rdr_json ~include_spans (rdr : Ir.rdr) =
  add_span ~include_spans rdr.span
    [
      ("interface", interface_json ~include_spans rdr.interface);
      ("protocol", protocol_json rdr.protocol);
      ("source", address_json rdr.source);
      ("destination", address_json rdr.destination);
      ("port", port_json rdr.port);
      ("translation", address_json rdr.translation);
      ("translation_port", port_json rdr.translation_port);
    ]
  |> json_object

let anchor_json ~include_spans (anchor : Ir.anchor) =
  add_span ~include_spans anchor.span
    [
      ("name", json_string anchor.name);
      ("rules", json_list (rule_json ~include_spans) anchor.rules);
    ]
  |> json_object

let sort_by key values =
  List.sort (fun left right -> String.compare (key left) (key right)) values

let interface_key (interface : Ir.interface_ref) =
  match interface.name with
  | Some name -> name
  | None -> interface.device

let policy_json ~include_spans ~for_checksum (policy : Ir.t) =
  let interfaces =
    if for_checksum then sort_by interface_key policy.interfaces else policy.interfaces
  in
  let tables =
    if for_checksum then sort_by (fun (table : Ir.table) -> table.name) policy.tables
    else policy.tables
  in
  let queues =
    if for_checksum then sort_by (fun (queue : Ir.queue) -> queue.name) policy.queues
    else policy.queues
  in
  json_object
    [
      ("default_action", default_action_json policy.default_action);
      ("interfaces", json_list (interface_json ~include_spans) interfaces);
      ("tables", json_list (table_json ~include_spans ~for_checksum) tables);
      ("queues", json_list (queue_json ~include_spans) queues);
      ("nat", json_list (nat_json ~include_spans) policy.nats);
      ("rdr", json_list (rdr_json ~include_spans) policy.rdrs);
      ("anchors", json_list (anchor_json ~include_spans) policy.anchors);
      ("rules", json_list (rule_json ~include_spans) policy.rules);
    ]

let checksum_body policy = policy_json ~include_spans:false ~for_checksum:true policy

let checksum_of_ir policy =
  "md5:" ^ Digest.to_hex (Digest.string (schema ^ "\n" ^ checksum_body policy))

let of_ir policy = { schema; checksum = checksum_of_ir policy; policy }
let checksum plan = plan.checksum

let to_json plan =
  json_object
    [
      ("schema", json_string plan.schema);
      ("kind", json_string "semantic-policy");
      ("checksum", json_string plan.checksum);
      ("policy", policy_json ~include_spans:true ~for_checksum:false plan.policy);
    ]
  ^ "\n"
