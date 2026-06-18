type table_element = {
  value : string;
  packets : int option;
  bytes : int option;
}

val add : string -> string -> (unit, Nft.run_error) result

val add_with_runner :
  (Nft.invocation -> (string, Nft.run_error) result) ->
  string ->
  string ->
  (unit, Nft.run_error) result

val delete : string -> string -> (unit, Nft.run_error) result

val delete_with_runner :
  (Nft.invocation -> (string, Nft.run_error) result) ->
  string ->
  string ->
  (unit, Nft.run_error) result

val replace : string -> string list -> (unit, Nft.run_error) result

val replace_with_runner :
  (Nft.invocation -> (string, Nft.run_error) result) ->
  string ->
  string list ->
  (unit, Nft.run_error) result

val flush : string -> (unit, Nft.run_error) result
val counters : string -> (string, Nft.run_error) result
val parse_counters_output : string -> table_element list
val elements_to_json : table_element list -> string
