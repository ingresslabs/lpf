type family = Inet | Ip
type chain_type = Filter | Nat
type hook = Input | Forward | Output | Prerouting | Postrouting
type policy = Policy_accept | Policy_drop

type table = {
  family : family;
  name : string;
}

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
  | Log of string option
  | Snat of string
  | Dnat of string
  | Masquerade

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

val of_ir : Ir.t -> t
val of_plan : Plan.t -> t
val to_string : t -> string
val owned_ruleset_text : string -> string
val diff_text : intended:string -> observed:string -> string
val render_ir : Ir.t -> string
val render_plan : Plan.t -> string
