val string : string -> string
val int : int -> string
val list : ('a -> string) -> 'a list -> string
val option : ('a -> string) -> 'a option -> string
val field_object : (string * string) list -> string
