type entry = {
  key : string;
  value : string;
}

type t = entry list

let sysctl_dir = "/proc/sys"

let path_of_key key =
  Filename.concat sysctl_dir (String.concat "/" (String.split_on_char '.' key))

let read key =
  let path = path_of_key key in
  if Sys.file_exists path then
    let ic = open_in path in
    let value = Fun.protect ~finally:(fun () -> close_in ic)
        (fun () -> String.trim (really_input_string ic (in_channel_length ic))) in
    Ok value
  else Error (Printf.sprintf "sysctl %s not found at %s" key path)

let write key value =
  let path = path_of_key key in
  if Sys.file_exists path then
    try
      let oc = open_out path in
      Fun.protect ~finally:(fun () -> close_out oc) (fun () -> output_string oc (value ^ "\n"));
      Ok ()
    with e -> Error (Printf.sprintf "failed to write sysctl %s: %s" key (Printexc.to_string e))
  else Error (Printf.sprintf "sysctl %s not found at %s" key path)

let required_sysctls () =
  [
    "net.ipv4.ip_forward";
    "net.ipv4.conf.all.rp_filter";
    "net.ipv4.conf.default.rp_filter";
    "net.ipv6.conf.all.forwarding";
    "net.bridge.bridge-nf-call-iptables";
    "net.bridge.bridge-nf-call-ip6tables";
  ]

let check_required () =
  List.filter_map (fun key ->
    match read key with
    | Ok value -> Some { key; value }
    | Error _ -> None
  ) (required_sysctls ())

let snapshot () =
  List.filter_map (fun key ->
    match read key with
    | Ok value -> Some { key; value }
    | Error _ -> None
  ) (required_sysctls ())

let restore (entries : t) =
  let rec loop errors = function
    | [] -> if errors = [] then Ok () else Error (String.concat "; " (List.rev errors))
    | { key; value } :: rest ->
        match write key value with
        | Ok () -> loop errors rest
        | Error e -> loop (e :: errors) rest
  in
  loop [] entries

let of_json_line line =
  let key = History.find_json_value line "key" in
  let value = History.find_json_value line "value" in
  if key = "" then None else Some { key; value }

let of_json text =
  String.split_on_char '\n' text
  |> List.filter_map (fun line ->
    let line = String.trim line in
    if String.length line = 0 then None else of_json_line line)

let to_string (entries : t) =
  String.concat "\n"
    (List.map (fun e -> Printf.sprintf "%s = %s" e.key e.value) entries)

let diff ~intended ~observed =
  let intended_map = List.fold_left (fun acc e -> (e.key, e.value) :: acc) [] intended in
  let observed_map = List.fold_left (fun acc e -> (e.key, e.value) :: acc) [] observed in
  let changes = ref false in
  let buf = Buffer.create 256 in
  List.iter (fun (key, intended_value) ->
    match List.assoc_opt key observed_map with
    | Some observed_value when observed_value <> intended_value ->
        changes := true;
        Buffer.add_string buf (Printf.sprintf "-%s=%s\n" key observed_value);
        Buffer.add_string buf (Printf.sprintf "+%s=%s\n" key intended_value)
    | None ->
        changes := true;
        Buffer.add_string buf (Printf.sprintf "+%s=%s (missing)\n" key intended_value)
    | _ -> ()
  ) intended_map;
  List.iter (fun (key, observed_value) ->
    if not (List.mem_assoc key intended_map) then (
      changes := true;
      Buffer.add_string buf (Printf.sprintf "-%s=%s (extra)\n" key observed_value)
    )
  ) observed_map;
  if not !changes then "sysctl diff: no changes\n"
  else "sysctl diff: changes required\n" ^ Buffer.contents buf

let entry_json (e : entry) =
  Json_util.field_object
    [
      ("key", Json_util.string e.key);
      ("value", Json_util.string e.value);
    ]

let to_json (entries : t) =
  Json_util.list entry_json entries ^ "\n"
