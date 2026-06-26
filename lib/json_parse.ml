type json =
  | Object of (string * json) list
  | Array of json list
  | String of string
  | Number of float
  | Bool of bool
  | Null

type pos = { text : string; mutable i : int }

let make_pos text = { text; i = 0 }

let peek p =
  if p.i < String.length p.text then Some p.text.[p.i] else None

let advance p =
  if p.i < String.length p.text then begin
    let c = p.text.[p.i] in
    p.i <- p.i + 1;
    Some c
  end else None

let rec skip_whitespace p =
  match peek p with
  | Some (' ' | '\t' | '\n' | '\r') -> ignore (advance p); skip_whitespace p
  | _ -> ()

let expect_char p c =
  skip_whitespace p;
  match peek p with
  | Some c' when c' = c -> Ok (ignore (advance p))
  | Some c' -> Error (Printf.sprintf "expected '%c' but got '%c' at position %d" c c' p.i)
  | None -> Error (Printf.sprintf "expected '%c' but reached end of input" c)

let parse_string p =
  let buf = Buffer.create 64 in
  begin match advance p with
  | Some '"' -> ()
  | _ -> raise (Failure "expected opening quote")
  end;
  let rec loop () =
    match advance p with
    | None -> Error "unterminated string"
    | Some '"' -> Ok (Buffer.contents buf)
    | Some '\\' ->
      begin match advance p with
      | None -> Error "unterminated escape"
      | Some '"' -> Buffer.add_char buf '"'; loop ()
      | Some '\\' -> Buffer.add_char buf '\\'; loop ()
      | Some '/' -> Buffer.add_char buf '/'; loop ()
      | Some 'b' -> Buffer.add_char buf '\b'; loop ()
      | Some 'f' -> Buffer.add_char buf '\012'; loop ()
      | Some 'n' -> Buffer.add_char buf '\n'; loop ()
      | Some 'r' -> Buffer.add_char buf '\r'; loop ()
      | Some 't' -> Buffer.add_char buf '\t'; loop ()
      | Some 'u' ->
        let hex = Buffer.create 4 in
        for _ = 1 to 4 do
          match advance p with
          | Some c -> Buffer.add_char hex c
          | None -> ()
        done;
        begin match int_of_string_opt ("0x" ^ Buffer.contents hex) with
        | Some code ->
          Buffer.add_string buf (String.make 1 (Char.chr code));
          loop ()
        | None -> Error (Printf.sprintf "invalid unicode escape \\u%s" (Buffer.contents hex))
        end
      | Some c -> Buffer.add_char buf c; loop ()
      end
    | Some c -> Buffer.add_char buf c; loop ()
  in
  loop ()

let parse_number p =
  let buf = Buffer.create 32 in
  let rec loop () =
    match peek p with
    | Some ('0'..'9') | Some '.' | Some '-' | Some '+' | Some 'e' | Some 'E' ->
      begin match advance p with
      | Some c -> Buffer.add_char buf c; loop ()
      | None -> ()
      end
    | _ -> ()
  in
  loop ();
  let s = Buffer.contents buf in
  if s = "" then Error "expected number"
  else match float_of_string_opt s with
  | Some f -> Ok (Number f)
  | None -> Error (Printf.sprintf "invalid number: %s" s)

let rec parse_value p =
  skip_whitespace p;
  match peek p with
  | None -> Error "unexpected end of input"
  | Some '{' -> parse_object p
  | Some '[' -> parse_array p
  | Some '"' -> begin match parse_string p with Ok s -> Ok (String s) | Error e -> Error e end
  | Some ('t' | 'f') -> parse_bool p
  | Some 'n' -> parse_null p
  | Some _ -> parse_number p

and parse_object p =
  match expect_char p '{' with
  | Error e -> Error e
  | Ok () ->
    let rec loop acc =
      skip_whitespace p;
      match peek p with
      | Some '}' -> ignore (advance p); Ok (Object (List.rev acc))
      | Some ',' -> ignore (advance p); loop acc
      | Some _ ->
        begin match parse_string p with
        | Error e -> Error e
        | Ok key ->
          begin match expect_char p ':' with
          | Error e -> Error e
          | Ok () ->
            match parse_value p with
            | Error e -> Error e
            | Ok v -> loop ((key, v) :: acc)
          end
        end
      | None -> Error "unterminated object"
    in
    loop []

and parse_array p =
  match expect_char p '[' with
  | Error e -> Error e
  | Ok () ->
    let rec loop acc =
      skip_whitespace p;
      match peek p with
      | Some ']' -> ignore (advance p); Ok (Array (List.rev acc))
      | Some ',' -> ignore (advance p); loop acc
      | Some _ ->
        begin match parse_value p with
        | Error e -> Error e
        | Ok v -> loop (v :: acc)
        end
      | None -> Error "unterminated array"
    in
    loop []

and parse_bool p =
  skip_whitespace p;
  let buf = Buffer.create 5 in
  let rec loop () =
    match peek p with
    | Some (('a'..'z') as c) -> ignore (advance p); Buffer.add_char buf c; loop ()
    | _ -> ()
  in
  loop ();
  match Buffer.contents buf with
  | "true" -> Ok (Bool true)
  | "false" -> Ok (Bool false)
  | s -> Error (Printf.sprintf "invalid token: %s" s)

and parse_null p =
  skip_whitespace p;
  let buf = Buffer.create 4 in
  for _ = 1 to 4 do
    match advance p with Some c -> Buffer.add_char buf c | None -> ()
  done;
  if Buffer.contents buf = "null" then Ok Null
  else Error (Printf.sprintf "expected null but got: %s" (Buffer.contents buf))

let parse text =
  let p = make_pos text in
  match parse_value p with
  | Ok v ->
    skip_whitespace p;
    if peek p <> None then
      Error (Printf.sprintf "trailing content at position %d" p.i)
    else Ok v
  | Error e -> Error e

let rec lookup json path =
  match path with
  | [] -> Some json
  | key :: rest ->
    match json with
    | Object fields ->
      begin match List.assoc_opt key fields with
      | Some v -> lookup v rest
      | None -> None
      end
    | _ -> None

let string_value = function
  | String s -> Some s
  | _ -> None

let bool_value = function
  | Bool b -> Some b
  | _ -> None

let float_value = function
  | Number f -> Some f
  | _ -> None

let int_value = function
  | Number f -> Some (int_of_float f)
  | _ -> None

let rec string_of_json = function
  | Null -> "null"
  | Bool b -> string_of_bool b
  | Number f ->
    if Float.is_integer f then string_of_int (int_of_float f)
    else Printf.sprintf "%.6g" f
  | String s ->
    let escaped = String.concat ""
      (List.map (function
        | '"' -> "\\\""
        | '\\' -> "\\\\"
        | '\n' -> "\\n"
        | '\r' -> "\\r"
        | '\t' -> "\\t"
        | c -> String.make 1 c)
      (List.init (String.length s) (String.get s)))
    in "\"" ^ escaped ^ "\""
  | Array items ->
    "[" ^ String.concat ", " (List.map string_of_json items) ^ "]"
  | Object fields ->
    "{" ^ String.concat ", "
      (List.map (fun (k, v) -> "\"" ^ k ^ "\": " ^ string_of_json v) fields) ^ "}"
