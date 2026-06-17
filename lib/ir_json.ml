let span_json (span : Policy.span) =
  Json_util.field_object
    [
      ("line", Json_util.int span.line);
      ("column", Json_util.int span.column);
      ("end_column", Json_util.int span.end_column);
    ]

let add_span ~include_spans span fields =
  if include_spans then fields @ [ ("span", span_json span) ] else fields

let default_action_json = function
  | Policy.Default_pass -> Json_util.string "pass"
  | Policy.Default_deny -> Json_util.string "deny"

let action_json = function
  | Policy.Pass -> Json_util.string "pass"
  | Policy.Block -> Json_util.string "block"

let direction_json = function
  | Policy.In -> Json_util.string "in"
  | Policy.Out -> Json_util.string "out"

let protocol_json = function
  | Policy.Proto_any -> Json_util.string "any"
  | Policy.Proto_named name -> Json_util.string name

let log_json = function
  | Policy.Log_all -> Json_util.string "all"
  | Policy.Log_matches -> Json_util.string "matches"
  | Policy.Log_user -> Json_util.string "user"

let interface_json ~include_spans (interface : Ir.interface_ref) =
  add_span ~include_spans interface.span
    [
      ("name", Json_util.option Json_util.string interface.name);
      ("device", Json_util.string interface.device);
    ]
  |> Json_util.field_object

let address_json = function
  | Ir.Any -> Json_util.field_object [ ("kind", Json_util.string "any") ]
  | Ir.Literal value ->
      Json_util.field_object [ ("kind", Json_util.string "literal"); ("value", Json_util.string value) ]
  | Ir.Table name ->
      Json_util.field_object [ ("kind", Json_util.string "table"); ("name", Json_util.string name) ]

let port_json = function
  | Ir.Port_any -> Json_util.field_object [ ("kind", Json_util.string "any") ]
  | Ir.Range (lower, upper) ->
      Json_util.field_object
        [
          ("kind", Json_util.string "range");
          ("lower", Json_util.int lower);
          ("upper", Json_util.int upper);
        ]

let table_json ~include_spans ~for_checksum (table : Ir.table) =
  let entries =
    if for_checksum then List.sort String.compare table.entries else table.entries
  in
  add_span ~include_spans table.span
    [
      ("name", Json_util.string table.name);
      ("entries", Json_util.list Json_util.string entries);
    ]
  |> Json_util.field_object

let queue_json ~include_spans (queue : Ir.queue) =
  add_span ~include_spans queue.span
    [
      ("name", Json_util.string queue.name);
      ("interface", interface_json ~include_spans queue.interface);
      ("bandwidth", Json_util.string queue.bandwidth);
      ("parent", Json_util.option Json_util.string queue.parent);
    ]
  |> Json_util.field_object

let route_to_json ~include_spans (gateway, interface) =
  Json_util.field_object
    [
      ("gateway", address_json gateway);
      ("interface", Json_util.option (interface_json ~include_spans) interface);
    ]

let rule_json ~include_spans (rule : Ir.rule) =
  add_span ~include_spans rule.span
    [
      ("action", action_json rule.action);
      ("direction", Json_util.option direction_json rule.direction);
      ("interface", Json_util.option (interface_json ~include_spans) rule.interface);
      ("protocol", protocol_json rule.protocol);
      ("source", address_json rule.source);
      ("destination", address_json rule.destination);
      ("port", port_json rule.port);
      ("keep_state", if rule.keep_state then "true" else "false");
      ("log", Json_util.option log_json rule.log);
      ("queue", Json_util.option Json_util.string rule.queue);
      ("route_to", Json_util.option (route_to_json ~include_spans) rule.route_to);
    ]
  |> Json_util.field_object

let nat_json ~include_spans (nat : Ir.nat) =
  add_span ~include_spans nat.span
    [
      ("interface", interface_json ~include_spans nat.interface);
      ("protocol", protocol_json nat.protocol);
      ("source", address_json nat.source);
      ("destination", address_json nat.destination);
      ("translation", address_json nat.translation);
    ]
  |> Json_util.field_object

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
  |> Json_util.field_object

let anchor_json ~include_spans (anchor : Ir.anchor) =
  add_span ~include_spans anchor.span
    [
      ("name", Json_util.string anchor.name);
      ("rules", Json_util.list (rule_json ~include_spans) anchor.rules);
    ]
  |> Json_util.field_object

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
  Json_util.field_object
    [
      ("default_action", default_action_json policy.default_action);
      ("interfaces", Json_util.list (interface_json ~include_spans) interfaces);
      ("tables", Json_util.list (table_json ~include_spans ~for_checksum) tables);
      ("queues", Json_util.list (queue_json ~include_spans) queues);
      ("nat", Json_util.list (nat_json ~include_spans) policy.nats);
      ("rdr", Json_util.list (rdr_json ~include_spans) policy.rdrs);
      ("anchors", Json_util.list (anchor_json ~include_spans) policy.anchors);
      ("rules", Json_util.list (rule_json ~include_spans) policy.rules);
    ]

let checksum_body policy = policy_json ~include_spans:false ~for_checksum:true policy

let checksum_of_ir schema policy =
  "md5:" ^ Digest.to_hex (Digest.string (schema ^ "\n" ^ checksum_body policy))
