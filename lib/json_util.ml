let string text =
  let buffer = Buffer.create (String.length text + 2) in
  Buffer.add_char buffer '"';
  String.iter
    (function
      | '"' -> Buffer.add_string buffer "\\\""
      | '\\' -> Buffer.add_string buffer "\\\\"
      | '\b' -> Buffer.add_string buffer "\\b"
      | '\012' -> Buffer.add_string buffer "\\f"
      | '\n' -> Buffer.add_string buffer "\\n"
      | '\r' -> Buffer.add_string buffer "\\r"
      | '\t' -> Buffer.add_string buffer "\\t"
      | character ->
          let code = Char.code character in
          if code < 0x20 then Buffer.add_string buffer (Printf.sprintf "\\u%04x" code)
          else Buffer.add_char buffer character)
    text;
  Buffer.add_char buffer '"';
  Buffer.contents buffer

let int value = string_of_int value
let list render values = "[" ^ String.concat "," (List.map render values) ^ "]"

let option render = function
  | None -> "null"
  | Some value -> render value

let field_object fields =
  "{"
  ^ String.concat ","
      (List.map (fun (name, value) -> string name ^ ":" ^ value) fields)
  ^ "}"
