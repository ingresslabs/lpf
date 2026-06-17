val interface_json : include_spans:bool -> Ir.interface_ref -> string
val address_json : Ir.address -> string
val port_json : Ir.port_range -> string
val rule_json : include_spans:bool -> Ir.rule -> string
val nat_json : include_spans:bool -> Ir.nat -> string
val rdr_json : include_spans:bool -> Ir.rdr -> string
val anchor_json : include_spans:bool -> Ir.anchor -> string
val policy_json : include_spans:bool -> for_checksum:bool -> Ir.t -> string
val checksum_of_ir : string -> Ir.t -> string
