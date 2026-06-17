type command =
  | Qdisc_add of { device : string; handle : string; parent : string; kind : string; default : int option }
  | Class_add of { device : string; classid : string; parent : string; kind : string; rate : string }

type t = command list

val queue_classid : Ir.queue list -> string -> string option
val compile : Ir.t -> t
val to_string : t -> string
val qdisc_show : string -> (string, Nft.run_error) result
val qdisc_show_with_runner : (Nft.invocation -> (string, Nft.run_error) result) -> string -> (string, Nft.run_error) result
val class_show : string -> (string, Nft.run_error) result
val class_show_with_runner : (Nft.invocation -> (string, Nft.run_error) result) -> string -> (string, Nft.run_error) result
