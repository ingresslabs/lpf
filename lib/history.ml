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

let history_file = Filename.concat "/var/lib/lpf" "history"

let entry_json (e : entry) =
  Json_util.field_object
    [
      ("id", Json_util.string e.id);
      ("timestamp", Json_util.string e.timestamp);
      ("operator", Json_util.string e.operator);
      ("policy_checksum", Json_util.string e.policy_checksum);
      ("policy_path", Json_util.string e.policy_path);
      ("test_result", Json_util.string e.test_result);
      ("rollback_available", (if e.rollback_available then "true" else "false"));
    ]

let to_json (h : t) = String.concat "\n" (List.map (fun e -> entry_json e) h)

let parse_json_string text =
  let text = String.trim text in
  if String.length text >= 2 && text.[0] = '"' && text.[String.length text - 1] = '"' then
    String.sub text 1 (String.length text - 2)
  else text

let find_json_value line key =
  let key_pattern = "\"" ^ key ^ "\":" in
  let rec search pos =
    if pos >= String.length line then ""
    else if String.length line - pos >= String.length key_pattern
         && String.sub line pos (String.length key_pattern) = key_pattern then
      let val_start = pos + String.length key_pattern in
      let val_text = String.sub line val_start (String.length line - val_start) in
      let val_text = String.trim val_text in
      if String.length val_text > 0 && val_text.[0] = '"' then
        let rec find_end i =
          if i >= String.length val_text then String.length val_text
          else if val_text.[i] = '"' && (i = 0 || val_text.[i-1] <> '\\') then i
          else find_end (i + 1)
        in
        let end_idx = find_end 1 in
        if end_idx < String.length val_text then
          parse_json_string (String.sub val_text 0 (end_idx + 1))
        else parse_json_string val_text
      else
        let rec find_comma i =
          if i >= String.length val_text then String.length val_text
          else if val_text.[i] = ',' || val_text.[i] = '}' then i
          else find_comma (i + 1)
        in
        String.trim (String.sub val_text 0 (find_comma 0))
    else search (pos + 1)
  in
  search 0

let load () =
  if not (Sys.file_exists history_file) then Ok []
  else
    try
      let ic = open_in history_file in
      let rec read_lines acc =
        match input_line ic with
        | line ->
            let line = String.trim line in
            if line = "" then read_lines acc
            else
              let entry = {
                id = find_json_value line "id";
                timestamp = find_json_value line "timestamp";
                operator = find_json_value line "operator";
                policy_checksum = find_json_value line "policy_checksum";
                policy_path = find_json_value line "policy_path";
                test_result = find_json_value line "test_result";
                rollback_available = (find_json_value line "rollback_available" = "true");
              } in
              read_lines (entry :: acc)
        | exception End_of_file ->
            close_in ic;
            Ok (List.rev acc)
      in
      read_lines []
    with e -> Error (Printexc.to_string e)

let save (h : t) =
  let json = to_json h in
  try
    let out = open_out history_file in
    Fun.protect ~finally:(fun () -> close_out out) (fun () -> output_string out (json ^ "\n"));
    Ok ()
  with e -> Error (Printexc.to_string e)

let add entry h = entry :: h

let to_string (h : t) =
  let header = Printf.sprintf "%-20s %-20s %-15s %-10s %s" "ID" "TIMESTAMP" "OPERATOR" "RESULT" "POLICY" in
  let rows = List.map (fun e ->
    Printf.sprintf "%-20s %-20s %-15s %-10s %s"
      (String.sub e.id 0 (min (String.length e.id) 20))
      (String.sub e.timestamp 0 (min (String.length e.timestamp) 20))
      e.operator e.test_result e.policy_path
  ) h in
  String.concat "\n" (header :: rows)
