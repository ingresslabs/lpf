type span = { file : string option; line : int; column : int; end_column : int }
type severity = Diag_error | Diag_warning
type diagnostic = { severity : severity; span : span; message : string }
type default_action = Default_pass | Default_deny
type direction = In | Out
type action = Pass | Block | Reject
type protocol = Proto_any | Proto_named of string

type reference =
  | Any
  | Literal of string
  | Table_ref of string
  | Macro_ref of string

type port =
  | Port_any
  | Port_number of int
  | Port_range of int * int
  | Port_macro of string

type interface_decl = { name : string; device : string; span : span }
type macro = { name : string; value : string; span : span }
type table = { name : string; entries : string list; span : span }
type log_option = Log_all | Log_matches | Log_user

type rule = {
  action : action;
  direction : direction option;
  interface : reference option;
  interface_span : span option;
  protocol : protocol;
  protocol_span : span option;
  source : reference;
  source_span : span;
  destination : reference;
  destination_span : span;
  port : port;
  port_span : span option;
  keep_state : bool;
  log : log_option option;
  log_span : span option;
  queue : string option;
  queue_span : span option;
  route_to : (reference * reference option) option;
  route_to_span : span option;
  route_to_gateway_span : span option;
  route_to_interface_span : span option;
  span : span;
}

type nat = {
  interface : reference;
  interface_span : span;
  protocol : protocol;
  protocol_span : span option;
  source : reference;
  source_span : span;
  destination : reference;
  destination_span : span;
  translation : reference;
  translation_span : span;
  span : span;
}

type rdr = {
  interface : reference;
  interface_span : span;
  protocol : protocol;
  protocol_span : span option;
  source : reference;
  source_span : span;
  destination : reference;
  destination_span : span;
  port : port;
  port_span : span option;
  translation : reference;
  translation_span : span;
  translation_port : port;
  translation_port_span : span option;
  span : span;
}

type queue = {
  name : string;
  name_span : span;
  interface : reference;
  interface_span : span;
  bandwidth : string;
  bandwidth_span : span option;
  parent : string option;
  parent_span : span option;
  span : span;
}

type anchor = {
  name : string;
  name_span : span;
  rules : rule list;
  span : span;
}

type policy = {
  default_action : default_action option;
  interfaces : interface_decl list;
  macros : macro list;
  tables : table list;
  nats : nat list;
  rdrs : rdr list;
  queues : queue list;
  anchors : anchor list;
  rules : rule list;
}

type check_result = { policy : policy option; diagnostics : diagnostic list }

val empty_policy : policy
