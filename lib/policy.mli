type span = {
  file : string option;
  line : int;
  column : int;
  end_column : int;
}

type severity = Diag_error | Diag_warning

type diagnostic = {
  severity : severity;
  span : span;
  message : string;
}

type default_action = Default_pass | Default_deny
type direction = In | Out
type action = Pass | Block
type protocol = Proto_any | Proto_named of string

type reference =
  | Any
  | Literal of string
  | Table_ref of string
  | Macro_ref of string

type port =
  | Port_any
  | Port_number of int
  | Port_macro of string

type interface_decl = {
  name : string;
  device : string;
  span : span;
}

type macro = {
  name : string;
  value : string;
  span : span;
}

type table = {
  name : string;
  entries : string list;
  span : span;
}

type rule = {
  action : action;
  direction : direction option;
  interface : reference option;
  protocol : protocol;
  source : reference;
  destination : reference;
  port : port;
  keep_state : bool;
  span : span;
}

type nat = {
  interface : reference;
  protocol : protocol;
  source : reference;
  destination : reference;
  translation : reference;
  span : span;
}

type rdr = {
  interface : reference;
  protocol : protocol;
  source : reference;
  destination : reference;
  port : port;
  translation : reference;
  translation_port : port;
  span : span;
}

type policy = {
  default_action : default_action option;
  interfaces : interface_decl list;
  macros : macro list;
  tables : table list;
  nats : nat list;
  rdrs : rdr list;
  rules : rule list;
}

type check_result = {
  policy : policy option;
  diagnostics : diagnostic list;
}

val parse : ?file:string -> string -> check_result
val validate : policy -> diagnostic list
val check : ?file:string -> string -> check_result
val format : policy -> string
val format_check_result : check_result -> string
val diagnostic_to_string : diagnostic -> string

