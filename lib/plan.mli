type t = { schema : string; checksum : string; policy : Ir.t }

val schema : string
val of_ir : Ir.t -> t
val checksum : t -> string
val to_json : t -> string
