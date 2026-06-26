type json =
  | Object of (string * json) list
  | Array of json list
  | String of string
  | Number of float
  | Bool of bool
  | Null

val parse : string -> (json, string) result
val lookup : json -> string list -> json option
val string_value : json -> string option
val bool_value : json -> bool option
val float_value : json -> float option
val int_value : json -> int option
val string_of_json : json -> string
