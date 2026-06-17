type element = string

val add : string -> string -> (unit, Nft.run_error) result
val add_with_runner : (Nft.invocation -> (string, Nft.run_error) result) -> string -> string -> (unit, Nft.run_error) result
val delete : string -> string -> (unit, Nft.run_error) result
val delete_with_runner : (Nft.invocation -> (string, Nft.run_error) result) -> string -> string -> (unit, Nft.run_error) result
val replace : string -> string list -> (unit, Nft.run_error) result
val replace_with_runner : (Nft.invocation -> (string, Nft.run_error) result) -> string -> string list -> (unit, Nft.run_error) result
val flush : string -> (unit, Nft.run_error) result
val flush_with_runner : (Nft.invocation -> (string, Nft.run_error) result) -> string -> (unit, Nft.run_error) result
val counters : string -> (string, Nft.run_error) result
val counters_with_runner : (Nft.invocation -> (string, Nft.run_error) result) -> string -> (string, Nft.run_error) result
