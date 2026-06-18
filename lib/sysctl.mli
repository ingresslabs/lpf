type entry = {
  key : string;
  value : string;
}

type t = entry list

val read : string -> (string, string) result
val write : string -> string -> (unit, string) result
val required_sysctls : unit -> string list
val check_required : unit -> entry list
val snapshot : unit -> entry list
val restore : t -> (unit, string) result
val to_string : t -> string
val diff : intended:t -> observed:t -> string
val to_json : t -> string
val of_json : string -> entry list
val of_json_line : string -> entry option
