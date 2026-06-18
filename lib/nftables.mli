type family = Inet | Ip
type chain_type = Filter | Nat
type hook = Input | Forward | Output | Prerouting | Postrouting
type policy = Policy_accept | Policy_drop
type table = { family : family; name : string }

type chain = {
  table : string;
  name : string;
  chain_type : chain_type option;
  hook : hook option;
  priority : int option;
  policy : policy option;
}

type set = {
  table : string;
  name : string;
  set_type : string;
  flags : string list;
  elements : string list;
}

type expression =
  | Meta of string * string
  | Payload of string * string * string
  | Ct_state of string list

type statement =
  | Accept
  | Drop
  | Reject
  | Log of string option
  | Snat of string
  | Dnat of string
  | Masquerade
  | Meta_priority_set of string
  | Meta_mark_set of int

type rule = {
  table : string;
  chain : string;
  expressions : expression list;
  statements : statement list;
  comment : string option;
}

type t = {
  tables : table list;
  chains : chain list;
  sets : set list;
  rules : rule list;
}

val owned_ruleset_text : string -> string

type diff_result = { changes_required : bool; text : string }

val diff : intended:string -> observed:string -> diff_result
val diff_text : intended:string -> observed:string -> string
val render_plan : Plan.t -> string
