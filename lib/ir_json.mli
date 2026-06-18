val rule_json : include_spans:bool -> Ir.rule -> string
val nat_json : include_spans:bool -> Ir.nat -> string
val rdr_json : include_spans:bool -> Ir.rdr -> string
val policy_json : include_spans:bool -> for_checksum:bool -> Ir.t -> string
val checksum_of_ir : string -> Ir.t -> string
