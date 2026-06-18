open Policy_types

val format : policy -> string
val format_check_result : check_result -> string
val diagnostic_to_string : diagnostic -> string
val diagnostic_to_json : diagnostic -> string
val check_result_to_json : check_result -> string
val string_of_action : action -> string
