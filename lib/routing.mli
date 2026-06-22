type command =
  | Ip_rule_add of { mark : int; table : int }
  | Ip_route_add_default of {
      gateway : string;
      device : string option;
      table : int;
    }

type t = command list
type diff_result = { changes_required : bool; text : string }

val mark_for_target : Ir.t -> Ir.address * Ir.interface_ref option -> int option
val compile : Ir.t -> t
val to_string : t -> string
val to_batch_string : t -> string

val diff :
  intended:t ->
  observed_rules:Ip.observed_rule list ->
  observed_routes:Ip.observed_route list ->
  diff_result
