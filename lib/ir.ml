open Policy

type interface_ref = {
  name : string option;
  device : string;
  span : span;
}

type address =
  | Any
  | Literal of string
  | Table of string

type port_range =
  | Port_any
  | Range of int * int

type table = {
  name : string;
  entries : string list;
  span : span;
}

type queue = {
  name : string;
  interface : interface_ref;
  bandwidth : string;
  parent : string option;
  span : span;
}

type rule = {
  action : action;
  direction : direction option;
  interface : interface_ref option;
  protocol : protocol;
  source : address;
  destination : address;
  port : port_range;
  keep_state : bool;
  log : log_option option;
  queue : string option;
  route_to : (address * interface_ref option) option;
  span : span;
}

type nat = {
  interface : interface_ref;
  protocol : protocol;
  source : address;
  destination : address;
  translation : address;
  span : span;
}

type rdr = {
  interface : interface_ref;
  protocol : protocol;
  source : address;
  destination : address;
  port : port_range;
  translation : address;
  translation_port : port_range;
  span : span;
}

type anchor = {
  name : string;
  rules : rule list;
  span : span;
}

type t = {
  default_action : default_action;
  interfaces : interface_ref list;
  tables : table list;
  queues : queue list;
  nats : nat list;
  rdrs : rdr list;
  anchors : anchor list;
  rules : rule list;
}

let diag span message = { severity = Diag_error; span; message }

let find_interface (policy : Policy.policy) name =
  List.find_opt
    (fun (interface : interface_decl) -> String.equal interface.name name)
    policy.interfaces

let interface_ref_of_decl (interface : interface_decl) =
  { name = Some interface.name; device = interface.device; span = interface.span }

let resolve_reference (policy : Policy.policy) span = function
  | Policy.Any -> Ok Any
  | Policy.Literal value -> Ok (Literal value)
  | Policy.Table_ref name ->
      if List.exists (fun (table : Policy.table) -> String.equal table.name name) policy.tables then
        Ok (Table name)
      else Error [ diag span ("unknown table `<" ^ name ^ ">`") ]
  | Policy.Macro_ref name -> (
      match List.find_opt (fun (macro : macro) -> String.equal macro.name name) policy.macros with
      | Some macro -> Ok (Literal macro.value)
      | None -> Error [ diag span ("unknown macro `$" ^ name ^ "`") ])

let resolve_interface (policy : Policy.policy) span = function
  | None -> Ok None
  | Some reference -> (
      match resolve_reference policy span reference with
      | Ok Any -> Error [ diag span "interface cannot be `any` in typed IR" ]
      | Ok (Literal name) -> (
          match find_interface policy name with
          | Some interface -> Ok (Some (interface_ref_of_decl interface))
          | None -> Ok (Some { name = None; device = name; span }))
      | Ok (Table name) ->
          Error [ diag span ("interface matcher cannot use table `<" ^ name ^ ">`") ]
      | Error diagnostics -> Error diagnostics)

let require_interface (policy : Policy.policy) span reference context =
  match resolve_interface policy span (Some reference) with
  | Ok (Some interface) -> Ok interface
  | Ok None -> Error [ diag span (context ^ " requires an interface") ]
  | Error diagnostics -> Error diagnostics

let resolve_port (policy : Policy.policy) span = function
  | Policy.Port_any -> Ok Port_any
  | Policy.Port_number number -> Ok (Range (number, number))
  | Policy.Port_macro name -> (
      match List.find_opt (fun (macro : macro) -> String.equal macro.name name) policy.macros with
      | Some macro -> (
          match int_of_string_opt macro.value with
          | Some number when number >= 1 && number <= 65535 -> Ok (Range (number, number))
          | _ ->
              Error
                [ diag span ("port macro `$" ^ name ^ "` has invalid value `" ^ macro.value ^ "`") ])
      | None -> Error [ diag span ("unknown port macro `$" ^ name ^ "`") ])

let collect_results results =
  let values, diagnostics =
    List.fold_left
      (fun (values, diagnostics) -> function
        | Ok value -> (value :: values, diagnostics)
        | Error new_diagnostics -> (values, new_diagnostics @ diagnostics))
      ([], []) results
  in
  match diagnostics with
  | [] -> Ok (List.rev values)
  | _ -> Error (List.rev diagnostics)

let of_interface interface = interface_ref_of_decl interface

let of_table (table : Policy.table) =
  { name = table.name; entries = table.entries; span = table.span }

let of_queue (policy : Policy.policy) (queue : Policy.queue) =
  let ( let* ) = Result.bind in
  let* interface = require_interface policy queue.interface_span queue.interface "queue" in
  Ok
    {
      name = queue.name;
      interface;
      bandwidth = queue.bandwidth;
      parent = queue.parent;
      span = queue.span;
    }

let of_rule (policy : Policy.policy) (rule : Policy.rule) =
  let ( let* ) = Result.bind in
  let* interface =
    resolve_interface policy (Option.value rule.interface_span ~default:rule.span) rule.interface
  in
  let* source = resolve_reference policy rule.source_span rule.source in
  let* destination = resolve_reference policy rule.destination_span rule.destination in
  let* port = resolve_port policy (Option.value rule.port_span ~default:rule.span) rule.port in
  let* route_to =
    match rule.route_to with
    | None -> Ok None
    | Some (gateway, interface_ref) ->
        let* gateway =
          resolve_reference policy
            (Option.value rule.route_to_gateway_span ~default:rule.span)
            gateway
        in
        let* () =
          match gateway with
          | Literal _ -> Ok ()
          | Any -> Error [ diag rule.span "route-to gateway must be a literal IP address, not `any`" ]
          | Table _ -> Error [ diag rule.span "route-to gateway cannot reference a table" ]
        in
        let* interface =
          resolve_interface policy
            (Option.value rule.route_to_interface_span ~default:rule.span)
            interface_ref
        in
        Ok (Some (gateway, interface))
  in
  Ok
    {
      action = rule.action;
      direction = rule.direction;
      interface;
      protocol = rule.protocol;
      source;
      destination;
      port;
      keep_state = rule.keep_state;
      log = rule.log;
      queue = rule.queue;
      route_to;
      span = rule.span;
    }

let of_nat (policy : Policy.policy) (nat : Policy.nat) =
  let ( let* ) = Result.bind in
  let* interface = require_interface policy nat.interface_span nat.interface "nat" in
  let* source = resolve_reference policy nat.source_span nat.source in
  let* destination = resolve_reference policy nat.destination_span nat.destination in
  let* translation = resolve_reference policy nat.translation_span nat.translation in
  Ok { interface; protocol = nat.protocol; source; destination; translation; span = nat.span }

let of_rdr (policy : Policy.policy) (rdr : Policy.rdr) =
  let ( let* ) = Result.bind in
  let* interface = require_interface policy rdr.interface_span rdr.interface "rdr" in
  let* source = resolve_reference policy rdr.source_span rdr.source in
  let* destination = resolve_reference policy rdr.destination_span rdr.destination in
  let* port = resolve_port policy (Option.value rdr.port_span ~default:rdr.span) rdr.port in
  let* translation = resolve_reference policy rdr.translation_span rdr.translation in
  let* translation_port =
    resolve_port policy
      (Option.value rdr.translation_port_span ~default:rdr.span)
      rdr.translation_port
  in
  Ok
    {
      interface;
      protocol = rdr.protocol;
      source;
      destination;
      port;
      translation;
      translation_port;
      span = rdr.span;
    }

let of_anchor (policy : Policy.policy) (anchor : Policy.anchor) =
  match collect_results (List.map (of_rule policy) anchor.rules) with
  | Ok rules -> Ok { name = anchor.name; rules; span = anchor.span }
  | Error diagnostics -> Error diagnostics

let of_policy (policy : Policy.policy) =
  let ( let* ) = Result.bind in
  let default_action = Option.value policy.default_action ~default:Default_deny in
  let interfaces = List.map of_interface policy.interfaces in
  let tables = List.map of_table policy.tables in
  let* queues = collect_results (List.map (of_queue policy) policy.queues) in
  let* nats = collect_results (List.map (of_nat policy) policy.nats) in
  let* rdrs = collect_results (List.map (of_rdr policy) policy.rdrs) in
  let* anchors = collect_results (List.map (of_anchor policy) policy.anchors) in
  let* rules = collect_results (List.map (of_rule policy) policy.rules) in
  Ok { default_action; interfaces; tables; queues; nats; rdrs; anchors; rules }

let is_superset_direction superset subset =
  match (superset, subset) with
  | None, _ -> true
  | Some expected, Some actual -> expected = actual
  | Some _, None -> false

let is_superset_interface superset subset =
  match (superset, subset) with
  | None, _ -> true
  | Some expected, Some actual -> String.equal expected.device actual.device
  | Some _, None -> false

let is_superset_protocol superset subset =
  match (superset, subset) with
  | Proto_any, _ -> true
  | Proto_named expected, Proto_named actual -> String.equal expected actual
  | Proto_named _, Proto_any -> false

let is_superset_address superset subset =
  match (superset, subset) with
  | Any, _ -> true
  | Literal expected, Literal actual -> String.equal expected actual
  | Table expected, Table actual -> String.equal expected actual
  | _, _ -> false

let is_superset_port superset subset =
  match (superset, subset) with
  | Port_any, _ -> true
  | Range (min_expected, max_expected), Range (min_actual, max_actual) ->
      min_expected <= min_actual && max_expected >= max_actual
  | _, _ -> false

let shadows earlier later =
  is_superset_direction earlier.direction later.direction
  && is_superset_interface earlier.interface later.interface
  && is_superset_protocol earlier.protocol later.protocol
  && is_superset_address earlier.source later.source
  && is_superset_address earlier.destination later.destination
  && is_superset_port earlier.port later.port

let shadow_diagnostics_rules rules =
  let rec check_shadows seen diagnostics = function
    | [] -> diagnostics
    | rule :: rest -> (
        match List.find_opt (fun earlier -> shadows earlier rule) seen with
        | Some earlier ->
            let diagnostic =
              {
                severity = Diag_warning;
                span = rule.span;
                message =
                  Printf.sprintf "rule is completely shadowed by rule at line %d"
                    earlier.span.line;
              }
            in
            check_shadows (rule :: seen) (diagnostic :: diagnostics) rest
        | None -> check_shadows (rule :: seen) diagnostics rest)
  in
  check_shadows [] [] rules |> List.rev

let shadow_diagnostics ir =
  let anchor_diagnostics =
    List.concat_map (fun (anchor : anchor) -> shadow_diagnostics_rules anchor.rules) ir.anchors
  in
  shadow_diagnostics_rules ir.rules @ anchor_diagnostics
