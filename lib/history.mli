type entry = {
  id : string;
  timestamp : string;
  operator : string;
  policy_checksum : string;
  policy_path : string;
  test_result : string;
  rollback_available : bool;
}

type t = entry list

val load : unit -> (t, string) result
val save : t -> (unit, string) result
val add : entry -> t -> t
val to_string : t -> string
val to_json : t -> string
val find_json_value : string -> string -> string
