type packet = {
  direction : Policy.direction;
  interface : string;
  protocol : Policy.protocol;
  source : string;
  destination : string;
  port : int option;
}

type explanation = {
  packet : packet;
  decision : Policy.action;
  matching_rule : Ir.rule option;
  shadowed_by : Ir.rule option;
  nat : Ir.nat option;
  rdr : Ir.rdr option;
  route_to : (Ir.address * Ir.interface_ref option) option;
  queue : string option;
  log : Policy.log_option option;
}

val explain : Ir.t -> packet -> explanation
val to_string : explanation -> string
val to_json : explanation -> string

(* Address matching (literal equality, IPv4 CIDR containment, and table/set
   membership) reused by alternate backends to stay in lockstep with the IR. *)
val match_address : Ir.t -> Ir.address -> string -> bool
