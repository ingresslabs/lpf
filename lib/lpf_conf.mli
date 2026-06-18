type t = { var_dir : string; max_history : int }

val default : t
val load : unit -> t
