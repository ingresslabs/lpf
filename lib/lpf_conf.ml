type t = { var_dir : string; max_history : int }

let default =
  {
    var_dir = (try Sys.getenv "LPF_VAR_DIR" with Not_found -> "/var/lib/lpf");
    max_history = 100;
  }

let conf_path () = try Sys.getenv "LPF_CONF" with Not_found -> "/etc/lpf.conf"

let parse_line line acc =
  let line = String.trim line in
  if String.length line = 0 || line.[0] = '#' then acc
  else
    match String.split_on_char '=' line with
    | key_parts :: value_parts -> (
        let key = String.trim key_parts in
        let value = String.trim (String.concat "=" value_parts) in
        match key with
        | "lpf_var_dir" -> { acc with var_dir = value }
        | "max_history" -> (
            match int_of_string_opt value with
            | Some n -> { acc with max_history = n }
            | None -> acc)
        | _ -> acc)
    | _ -> acc

let load () =
  let path = conf_path () in
  if not (Sys.file_exists path) then default
  else
    try
      let ic = open_in path in
      let rec read_lines acc =
        match input_line ic with
        | line -> read_lines (parse_line line acc)
        | exception End_of_file ->
            close_in ic;
            acc
      in
      read_lines default
    with _ -> default
