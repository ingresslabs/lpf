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

let var_dir = try Sys.getenv "LPF_VAR_DIR" with _ -> "/var/lib/lpf"
let history_file = Filename.concat var_dir "history"

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
  if String.length text >= 2 && text.[0] = '"' && text.[String.length text - 1] = '"' then
    String.sub text 1 (String.length text - 2)
  else text

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
              let line =
                if String.starts_with ~prefix:"{" line then
                  String.sub line 1 (String.length line - 1)
                else line
              in
              let line =
                if String.ends_with ~suffix:"}" line then
                  String.sub line 0 (String.length line - 1)
                else line
              in
              (* Very basic parser: "key": "value" *)
              let find_val key =
                let pattern = "\"" ^ key ^ "\":" in
                match String.index_opt line '"' with
                | None -> ""
                | Some _ -> (
                    match String.split_on_char ',' line |> List.find_opt (fun s -> String.contains s ':') with
                    | None -> ""
                    | Some _ ->
                        let parts = String.split_on_char ',' line in
                        match List.find_opt (String.starts_with ~prefix:pattern) parts with
                        | Some s ->
                            let v = String.sub s (String.length pattern) (String.length s - String.length pattern) in
                            parse_json_string v
                        | None -> "")
              in
              let entry = {
                id = find_val "id";
                timestamp = find_val "timestamp";
                operator = find_val "operator";
                policy_checksum = find_val "policy_checksum";
                policy_path = find_val "policy_path";
                test_result = find_val "test_result";
                rollback_available = (find_val "rollback_available" = "true");
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
