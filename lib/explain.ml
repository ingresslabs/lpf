open Policy
open Ir

type packet = {
  direction : direction;
  interface : string;
  protocol : protocol;
  source : string;
  destination : string;
  port : int option;
}

type explanation = {
  packet : packet;
  decision : action;
  matching_rule : rule option;
  shadowed_by : rule option;
  nat : nat option;
  rdr : rdr option;
  route_to : (address * interface_ref option) option;
  queue : string option;
  log : log_option option;
}

let match_address (ir : Ir.t) (addr : address) (value : string) =
  match addr with
  | Any -> true
  | Literal literal -> String.equal literal value
  | Table name ->
      (match List.find_opt (fun (t : table) -> String.equal t.name name) ir.tables with
       | Some t -> List.exists (String.equal value) t.entries
       | None -> false)

let match_port (range : port_range) (value : int option) =
  match range with
  | Port_any -> true
  | Range (low, high) ->
      (match value with
       | Some p -> p >= low && p <= high
       | None -> false)

let match_protocol (rule_proto : protocol) (pkt_proto : protocol) =
  match rule_proto with
  | Proto_any -> true
  | Proto_named n1 ->
      (match pkt_proto with
       | Proto_any -> false
       | Proto_named n2 -> String.equal n1 n2)

let match_rule (ir : Ir.t) (rule : rule) (pkt : packet) =
  let dir_match =
    match rule.direction with
    | None -> true
    | Some d -> d = pkt.direction
  in
  let iface_match =
    match rule.interface with
    | None -> true
    | Some i -> String.equal i.device pkt.interface
  in
  dir_match && iface_match &&
  match_protocol rule.protocol pkt.protocol &&
  match_address ir rule.source pkt.source &&
  match_address ir rule.destination pkt.destination &&
  match_port rule.port pkt.port

let match_nat (ir : Ir.t) (nat : nat) (pkt : packet) =
  (* NAT usually happens in Postrouting, for Out packets *)
  pkt.direction = Out &&
  String.equal nat.interface.device pkt.interface &&
  match_protocol nat.protocol pkt.protocol &&
  match_address ir nat.source pkt.source &&
  match_address ir nat.destination pkt.destination

let match_rdr (ir : Ir.t) (rdr : rdr) (pkt : packet) =
  (* RDR usually happens in Prerouting, for In packets *)
  pkt.direction = In &&
  String.equal rdr.interface.device pkt.interface &&
  match_protocol rdr.protocol pkt.protocol &&
  match_address ir rdr.source pkt.source &&
  match_address ir rdr.destination pkt.destination &&
  match_port rdr.port pkt.port

let find_shadow (ir : Ir.t) (pkt : packet) (matching_rule : rule option) =
  match matching_rule with
  | None -> None
  | Some matched ->
      let rec find_before seen = function
        | [] -> None
        | (r : rule) :: rest ->
            if r == matched then find_before seen rest
            else if match_rule ir r pkt then Some r
            else find_before seen rest
      in
      find_before [] ir.rules

let explain (ir : Ir.t) (pkt : packet) =
  (* 1. Check RDR (Prerouting) *)
  let rdr = List.find_opt (fun r -> match_rdr ir r pkt) ir.rdrs in
  
  (* 2. Check main rules (Input/Forward/Output) *)
  let matching_rule = List.find_opt (fun rule -> match_rule ir rule pkt) ir.rules in
  
  (* 3. Check NAT (Postrouting) *)
  let nat = List.find_opt (fun n -> match_nat ir n pkt) ir.nats in
  
  let decision =
    match matching_rule with
    | Some rule -> rule.action
    | None -> (
        match ir.default_action with
        | Default_pass -> Pass
        | Default_deny -> Block)
  in
  
  {
    packet = pkt;
    decision;
    matching_rule;
    shadowed_by = find_shadow ir pkt matching_rule;
    nat;
    rdr;
    route_to = (match matching_rule with Some r -> r.route_to | None -> None);
    queue = (match matching_rule with Some r -> r.queue | None -> None);
    log = (match matching_rule with Some r -> r.log | None -> None);
  }

let string_of_direction = function In -> "in" | Out -> "out"
let string_of_action = function Pass -> "pass" | Block -> "block"
let string_of_protocol = function Proto_any -> "any" | Proto_named n -> n

let address_to_string = function
  | Any -> "any"
  | Literal l -> l
  | Table t -> "<" ^ t ^ ">"

let explain_to_string e =
  let pkt = e.packet in
  let lines = [
    Printf.sprintf "Packet: %s %s proto %s from %s to %s%s"
      (string_of_direction pkt.direction)
      pkt.interface
      (string_of_protocol pkt.protocol)
      pkt.source
      pkt.destination
      (match pkt.port with Some p -> " port " ^ string_of_int p | None -> "");
    Printf.sprintf "Decision: %s" (string_of_action e.decision);
  ] in
  let lines =
    match e.matching_rule with
    | Some r -> lines @ [ Printf.sprintf "Matched rule: line %d" r.span.line ]
    | None -> lines @ [ "Matched rule: default action" ]
  in
  let lines =
    match e.rdr with
    | Some r -> lines @ [ Printf.sprintf "Matched RDR: line %d (redirect to %s)" r.span.line (address_to_string r.translation) ]
    | None -> lines
  in
  let lines =
    match e.nat with
    | Some n -> lines @ [ Printf.sprintf "Matched NAT: line %d (translate to %s)" n.span.line (address_to_string n.translation) ]
    | None -> lines
  in
  let lines =
    match e.route_to with
    | Some (gw, iface) ->
        let iface_str = match iface with Some i -> " (" ^ i.device ^ ")" | None -> "" in
        lines @ [ Printf.sprintf "Route-to: %s%s" (address_to_string gw) iface_str ]
    | None -> lines
  in
  let lines =
    match e.queue with
    | Some q -> lines @ [ Printf.sprintf "Queue: %s" q ]
    | None -> lines
  in
  String.concat "\n" lines

let to_string = explain_to_string

let packet_json (pkt : packet) =
  Json_util.field_object
    [
      ("direction", (match pkt.direction with In -> Json_util.string "in" | Out -> Json_util.string "out"));
      ("interface", Json_util.string pkt.interface);
      ("protocol", (match pkt.protocol with Proto_any -> Json_util.string "any" | Proto_named n -> Json_util.string n));
      ("source", Json_util.string pkt.source);
      ("destination", Json_util.string pkt.destination);
      ("port", Json_util.option Json_util.int pkt.port);
    ]

let to_json e =
  Json_util.field_object
    [
      ("packet", packet_json e.packet);
      ("decision", (match e.decision with Pass -> Json_util.string "pass" | Block -> Json_util.string "block"));
      ("matching_rule", Json_util.option (Ir_json.rule_json ~include_spans:true) e.matching_rule);
      ("nat", Json_util.option (Ir_json.nat_json ~include_spans:true) e.nat);
      ("rdr", Json_util.option (Ir_json.rdr_json ~include_spans:true) e.rdr);
    ]
