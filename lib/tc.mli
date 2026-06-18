type command =
  | Qdisc_add of { device : string; handle : string; parent : string; kind : string; default : int option }
  | Class_add of { device : string; classid : string; parent : string; kind : string; rate : string }

type t = command list

type diff_result = {
  changes_required : bool;
  text : string;
}

type observed_qdisc = {
  device : string;
  handle : string;
  kind : string;
}

type observed_class = {
  device : string;
  classid : string;
  parent : string;
  kind : string;
  rate : string;
}

val queue_classid : Ir.queue list -> string -> string option
val compile : Ir.t -> t
val to_string : t -> string
val qdisc_show : string -> (string, Nft.run_error) result
val qdisc_show_with_runner : (Nft.invocation -> (string, Nft.run_error) result) -> string -> (string, Nft.run_error) result
val class_show : string -> (string, Nft.run_error) result
val class_show_with_runner : (Nft.invocation -> (string, Nft.run_error) result) -> string -> (string, Nft.run_error) result
val delete : string -> (unit, Nft.run_error) result
val delete_with_runner : (Nft.invocation -> (string, Nft.run_error) result) -> string -> (unit, Nft.run_error) result
val parse_qdisc_show : string -> string -> observed_qdisc list
val parse_class_show : string -> string -> observed_class list
val diff : intended:t -> observed_qdisc:observed_qdisc list -> observed_class:observed_class list -> diff_result
