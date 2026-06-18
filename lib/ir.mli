open Policy

type interface_ref = { name : string option; device : string; span : span }
type address = Any | Literal of string | Table of string
type port_range = Port_any | Range of int * int
type table = { name : string; entries : string list; span : span }

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

type anchor = { name : string; rules : rule list; span : span }

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

val of_policy : policy -> (t, diagnostic list) result
val shadow_diagnostics : t -> diagnostic list
