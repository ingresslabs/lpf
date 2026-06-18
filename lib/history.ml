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

let history_file () = Filename.concat Lpf_conf.(load ()).var_dir "history"

let entry_json (e : entry) =
  Json_util.field_object
    [
      ("id", Json_util.string e.id);
      ("timestamp", Json_util.string e.timestamp);
      ("operator", Json_util.string e.operator);
      ("policy_checksum", Json_util.string e.policy_checksum);
      ("policy_path", Json_util.string e.policy_path);
      ("test_result", Json_util.string e.test_result);
      ("rollback_available", if e.rollback_available then "true" else "false");
    ]

let to_json (h : t) = String.concat "\n" (List.map (fun e -> entry_json e) h)

let parse_json_string text =
  let text = String.trim text in
  if
    String.length text >= 2
    && text.[0] = '"'
    && text.[String.length text - 1] = '"'
  then (
    let buf = Buffer.create (String.length text) in
    let rec unescape i =
      if i >= String.length text - 1 then ()
      else
        let c = text.[i] in
        if c = '\\' && i + 1 < String.length text then (
          match text.[i + 1] with
          | '"' ->
              Buffer.add_char buf '"';
              unescape (i + 2)
          | '\\' ->
              Buffer.add_char buf '\\';
              unescape (i + 2)
          | '/' ->
              Buffer.add_char buf '/';
              unescape (i + 2)
          | 'n' ->
              Buffer.add_char buf '\n';
              unescape (i + 2)
          | 'r' ->
              Buffer.add_char buf '\r';
              unescape (i + 2)
          | 't' ->
              Buffer.add_char buf '\t';
              unescape (i + 2)
          | _ ->
              Buffer.add_char buf c;
              unescape (i + 1))
        else (
          Buffer.add_char buf c;
          unescape (i + 1))
    in
    unescape 1;
    Buffer.contents buf)
  else text

let rec skip_whitespace line pos =
  if pos >= String.length line then pos
  else
    match line.[pos] with
    | ' ' | '\t' | '\n' | '\r' -> skip_whitespace line (pos + 1)
    | _ -> pos

let rec find_value_end line pos =
  if pos >= String.length line then String.length line
  else
    match line.[pos] with
    | '{' ->
        let rec skip_nested depth i =
          if i >= String.length line then String.length line
          else
            match line.[i] with
            | '{' -> skip_nested (depth + 1) (i + 1)
            | '}' when depth = 1 -> i
            | '}' -> skip_nested (depth - 1) (i + 1)
            | '"' ->
                let rec past_string j =
                  if j >= String.length line then String.length line
                  else if line.[j] = '"' && line.[j - 1] <> '\\' then j + 1
                  else past_string (j + 1)
                in
                skip_nested depth (past_string (i + 1))
            | _ -> skip_nested depth (i + 1)
        in
        skip_nested 1 (pos + 1)
    | '[' ->
        let rec skip_array depth i =
          if i >= String.length line then String.length line
          else
            match line.[i] with
            | '[' -> skip_array (depth + 1) (i + 1)
            | ']' when depth = 1 -> i
            | ']' -> skip_array (depth - 1) (i + 1)
            | '"' ->
                let rec past_string j =
                  if j >= String.length line then String.length line
                  else if line.[j] = '"' && line.[j - 1] <> '\\' then j + 1
                  else past_string (j + 1)
                in
                skip_array depth (past_string (i + 1))
            | _ -> skip_array depth (i + 1)
        in
        skip_array 1 (pos + 1)
    | ',' | '}' -> pos
    | ' ' | '\t' | '\n' | '\r' -> find_value_end line (pos + 1)
    | _ -> find_value_end line (pos + 1)

let find_json_value line key =
  let key_pattern = "\"" ^ key ^ "\"" in
  let rec search pos =
    if pos >= String.length line then ""
    else
      let pos = skip_whitespace line pos in
      if pos >= String.length line then ""
      else if
        line.[pos] = '"'
        && pos + String.length key_pattern <= String.length line
        && String.sub line pos (String.length key_pattern) = key_pattern
      then
        let after_key = pos + String.length key_pattern in
        let colon_pos = skip_whitespace line after_key in
        if colon_pos >= String.length line || line.[colon_pos] <> ':' then ""
        else
          let val_start = skip_whitespace line (colon_pos + 1) in
          if val_start >= String.length line then ""
          else if line.[val_start] = '"' then
            let rec find_string_end i =
              if i >= String.length line then String.length line
              else if line.[i] = '"' && line.[i - 1] <> '\\' then i
              else find_string_end (i + 1)
            in
            let end_idx = find_string_end (val_start + 1) in
            if end_idx < String.length line then
              parse_json_string
                (String.sub line val_start (end_idx - val_start + 1))
            else ""
          else if line.[val_start] = '{' || line.[val_start] = '[' then
            let end_idx = find_value_end line val_start in
            if end_idx < String.length line then
              String.sub line val_start (end_idx - val_start + 1)
            else ""
          else
            let end_idx = find_value_end line val_start in
            String.trim (String.sub line val_start (end_idx - val_start))
      else search (pos + 1)
  in
  search 0

let load () =
  if not (Sys.file_exists (history_file ())) then Ok []
  else
    try
      let ic = open_in (history_file ()) in
      let rec read_lines acc =
        match input_line ic with
        | line ->
            let line = String.trim line in
            if line = "" then read_lines acc
            else
              let entry =
                {
                  id = find_json_value line "id";
                  timestamp = find_json_value line "timestamp";
                  operator = find_json_value line "operator";
                  policy_checksum = find_json_value line "policy_checksum";
                  policy_path = find_json_value line "policy_path";
                  test_result = find_json_value line "test_result";
                  rollback_available =
                    find_json_value line "rollback_available" = "true";
                }
              in
              read_lines (entry :: acc)
        | exception End_of_file ->
            close_in ic;
            Ok (List.rev acc)
      in
      read_lines []
    with e -> Error (Printexc.to_string e)

let save (h : t) =
  let conf = Lpf_conf.load () in
  let h =
    if List.length h > conf.max_history then
      let rec take n = function
        | [] -> []
        | x :: xs -> if n <= 0 then [] else x :: take (n - 1) xs
      in
      take conf.max_history h
    else h
  in
  let json = to_json h in
  try
    let out = open_out (history_file ()) in
    Fun.protect
      ~finally:(fun () -> close_out out)
      (fun () -> output_string out (json ^ "\n"));
    Ok ()
  with e -> Error (Printexc.to_string e)

let add entry h = entry :: h

let to_string (h : t) =
  let header =
    Printf.sprintf "%-20s %-20s %-15s %-10s %s" "ID" "TIMESTAMP" "OPERATOR"
      "RESULT" "POLICY"
  in
  let rows =
    List.map
      (fun e ->
        Printf.sprintf "%-20s %-20s %-15s %-10s %s"
          (String.sub e.id 0 (min (String.length e.id) 20))
          (String.sub e.timestamp 0 (min (String.length e.timestamp) 20))
          e.operator e.test_result e.policy_path)
      h
  in
  String.concat "\n" (header :: rows)
