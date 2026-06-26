type command = Add | Del | Check | Version

type ipam_config = {
  ipam_type : string;
  ipam_subnet : string option;
  ipam_routes : (string * string option) list;
}

type policy_config = {
  policy_mode : string;
  default_action : string;
  cluster_policy_ref : string option;
  log_dropped : bool;
  audit_mode : bool;
}

type network_config = {
  cni_version : string;
  name : string;
  cnitype : string;
  ipam : ipam_config option;
  policy : policy_config option;
  prev_result : string option;
}

type ip_result = {
  ip_address : string;
  gateway : string option;
  routes : (string * string option) list;
  dns_nameservers : string list;
}

val parse_command : string -> (command, string) result
val parse_network_config : string -> (network_config, string) result

val handle_add : network_config -> string -> string -> string -> (ip_result, string) result
val handle_del : network_config -> string -> string -> string -> (unit, string) result
val handle_check : network_config -> string -> string -> string -> (unit, string) result
val handle_version : unit -> unit

val result_to_json : ip_result -> string
val error_result : int -> string -> string
